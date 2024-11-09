from scanpipe.pipelines import Pipeline
from scanpipe.models import VulnerablePaths

from os.path import commonprefix

from django.conf import settings
from django.db.models import Q
from packageurl import PackageURL
import json
import string
import logging
import requests
import networkx as nx

logger = logging.getLogger("scanpipe.pipes")

SUPPLYSHIELD_BASE = settings.SUPPLYSHIELD_BASE


class FindActionables(Pipeline):
    """
    Find which package needs to be upgraded to fix the vulnerable package.

    Path data is stored repository-wise.
    """

    @classmethod
    def steps(cls):
        return (
            cls.fetch_metadata_from_wasp,
            cls.sbom_to_graph,
            cls.fetch_all_packages,
            cls.find_parent_namespace,
            cls.get_vulnerable_packages,
            cls.find_paths_to_vulnerable_packages,
            cls.generate_actionables,
            cls.reset_actionables,
            cls.store_actionables,
        )

    def fetch_metadata_from_wasp(self):
        """
        Fetch metadata - repository_id, wasp_id, environment from WASP
        """
        self.wasp = self.project.wasp_uuid
        self.wasp_uuid = self.wasp.uuid
        self.repository_id = self.wasp.repository_id
        self.scan_environment = self.wasp.environment
        self.multiple_parents = []
        logger.info(
            f"{self.wasp_uuid}: Fetched WASP metadata for project {self.project.name} : {self.wasp.uuid}, {self.repository_id}, {self.scan_environment}"
        )

    def fetch_sbom(self):
        """
        Custom logic for fetching SBOM from S3
        """
        r = requests.get(
            f"{SUPPLYSHIELD_BASE}/blastradius/sbom?project_name="
            + str(self.project.name).replace("_no_commons", "")
        )
        return r.json()

    def find_parent_namespace(self):
        """
        For some java services we can use the group id as the parent namespace
        For other java services we need to find the parent namespace from immediate child components. This can be done in two ways:
            1. If all child components have the same namespace, we can use that as the parent namespace
            2. If all child components have different namespaces, we can use the common prefix as the parent namespace. However, this is not always accurate. 
            (TODO: Find a better way to handle this)
        For non-java services we need to fetch namespace from the parent package purl
        """
        G = self.sbom_graph
        parent_namespace = (
            self.sbom_json.get("metadata", []).get("component").get("group")
        )
        if not parent_namespace or len(parent_namespace) == 0:
            logger.info(f"{self.wasp_uuid}: Parent namespace not found using group")
            child_namespaces = set()
            childs = G.neighbors(self.parent_purl)

            for child in childs:
                child_namespace = PackageURL.from_string(child).namespace
                child_namespaces.add(child_namespace)
                self.multiple_parents.append(child)
                
            commonprefixes = commonprefix(list(child_namespaces))
            logger.info(
                    f"{self.wasp_uuid}: Identified child namespaces: {child_namespaces}, Common Prefix: {commonprefixes}"
            )
            if len(child_namespaces) == 1:
                parent_namespace = child_namespaces.pop()
                logger.info(
                    f"{self.wasp_uuid}: Identified parent namespace from child components: {parent_namespace}"
                )
            elif commonprefixes.count(".") > 2:
                parent_namespace = commonprefixes
                logger.info(
                    f"{self.wasp_uuid}: Identified parent namespace from child component using common prefix: {parent_namespace}"
                )
            else:
                logger.info(
                    f"{self.wasp_uuid}: Child components having different namespaces, and none of them have a common prefix."
                )
                logger.info(
                    f"{self.wasp_uuid}: Using package URL for detecting parent namespace"
                )
            parent_namespace = PackageURL.from_string(self.parent_purl).namespace
        self.parent_namespace = parent_namespace
        logger.info(
            f"{self.wasp_uuid}: Proceeding with parent namespace as: {self.parent_namespace}"
        )

    def fetch_all_packages(self):
        """
        Fetch all packages for the current project from the database
        """
        self.packages = self.project.discoveredpackages.all()
        print(
            f"{self.wasp_uuid}: Fetched {len(self.packages)} packages from the database."
        )

    def sbom_to_graph(self):
        """
        Parse the SBOM file into a graph object
        """
        cdx = self.fetch_sbom()
        self.sbom_json = cdx
        self.parent_purl = cdx.get("metadata", []).get("component").get("purl")
        components = cdx.get("components", [])
        dependencies = cdx.get("dependencies", [])
        G = nx.DiGraph()

        for component in components:
            name = component.get("bom-ref")
            G.add_node(name)

        # Ensure the parent node is added
        G.add_node(self.parent_purl)

        for dependency in dependencies:
            ref = dependency.get("ref")
            depends_on = dependency.get("dependsOn", [])
            for dep in depends_on:
                G.add_edge(ref, dep)

        self.sbom_graph = G
        logger.info(f"{self.wasp_uuid}: Identified parent purl: {self.parent_purl}")

    def translate_purl_to_id(self, purl):
        purl = PackageURL.from_string(purl)
        package = self.project.discoveredpackages.filter(
            name=purl.name,
            namespace=purl.namespace,
            version=purl.version,
            type=purl.type,
        ).first()
        if package:
            return package.id
        return package

    def get_vulnerable_packages(self):
        """
        Fetch all vulnerable packages that are used in the project
        """
        self.vulnerable_packages = self.project.discoveredpackages.filter(
            ~Q(affected_by_vulnerabilities=[])
        )
        logger.info(
            f"{self.wasp_uuid}: Processing Vulnerable packages: {len(self.vulnerable_packages)}"
        )

    def find_paths_to_package(self, parent_package, child_package):
        """
        Find all paths from the parent package to a given package
        """
        try:
            all_paths = list(
                nx.all_simple_paths(
                    self.sbom_graph, source=parent_package, target=child_package
                )
            )
        except nx.exception.NetworkXNoPath:
            logger.error(
                f"Error finding paths from {parent_package} to {child_package}"
            )
            return []
        return all_paths

    def is_commons(self, purl, svc_namespace):
        """
        Check if the package is a commons package.
        """
        # When service namespace is empty we cannot differentiate between commons and non-commons
        # we assume that the package is not a commons package.
        if svc_namespace is None:
            return False
        if svc_namespace in purl:
            return False

        for namespace in settings.COMMONS_NAMESPACES:
            if namespace in purl:
                return True
        return False

    def has_commons_in_path(self, path, svc_namespace):
        """
        Check if the path has a commons package.
        """
        for node in path:
            if self.is_commons(node, svc_namespace):
                return True
        return False

    def get_actionable(self, path):
        for node in path:
            purl = PackageURL.from_string(node)
            if purl.namespace == self.parent_namespace:
                continue
            if not self.parent_namespace or self.parent_namespace not in node:
                return node

    def find_paths_to_vulnerable_packages(self):
        """
        Find all paths from the parent package to all vulnerable packages
        """
        print("Starting find_paths_to_vulnerable_packages..")
        self.all_vulnerable_paths = []
        if self.multiple_parents:
            for parent in self.multiple_parents:
                for vulnerable_packge in self.vulnerable_packages:
                    self.all_vulnerable_paths += self.find_paths_to_package(
                        parent, str(vulnerable_packge)
                    )
        else:
            self.all_vulnerable_paths = self.find_paths_to_package(
                self.parent_purl,
                [
                    str(vulnerable_packge)
                    for vulnerable_packge in self.vulnerable_packages
                ],
            )
        print(
            f"Identified {len(self.all_vulnerable_paths)} paths to vulnerable packages."
        )

    def generate_actionables(self):
        """
        Create actionables with the paths to vulnerable packages
        seggregated by commons and non-commons.
        """
        print("Starting to generate actionables..")

        self.non_commons_paths = []
        self.commons_path = []

        for path in self.all_vulnerable_paths:
            actionable = self.get_actionable(path)
            if actionable is None:
                raise "Actionable not found for path"
            actionable_index = path.index(actionable)

            if self.has_commons_in_path(path, self.parent_namespace):
                self.commons_path.append({"p": path, "a": actionable_index})
            else:
                self.non_commons_paths.append({"p": path, "a": actionable_index})

        self.actionables = {
            "non_commons": self.non_commons_paths,
            "commons": self.commons_path,
        }

    def reset_actionables(self):
        """
        Reset the actionables field in the database
        """
        print(
            "Resetting actionables for repository:",
            self.repository_id,
            "env:",
            self.scan_environment,
        )
        VulnerablePaths.objects.filter(
            repository_id=self.repository_id, environment=self.scan_environment
        ).delete()

    def store_actionables(self):
        self.actionables = json.dumps(self.actionables)
        for package in self.packages:
            self.actionables = self.actionables.replace(
                str(package), str(self.translate_purl_to_id(str(package)))
            )

        self.actionables = json.loads(self.actionables)
        non_commons = []
        commons = []

        for path in self.actionables.get("non_commons", []):
            vulnerable_path = VulnerablePaths(
                repository_id=self.repository_id,
                project_name=self.project.name,
                path=path.get("p"),
                action_item=int(path.get("a")),
                vulnerable_package_id=path.get("p")[-1],
                has_commons_in_path=False,
                wasp_uuid=self.wasp_uuid,
                environment=self.scan_environment,
            )
            non_commons.append(vulnerable_path)

        for path in self.actionables.get("commons", []):
            vulnerable_path = VulnerablePaths(
                repository_id=self.repository_id,
                project_name=self.project.name,
                path=path.get("p"),
                action_item=int(path.get("a")),
                vulnerable_package_id=path.get("p")[-1],
                has_commons_in_path=True,
                wasp_uuid=self.wasp_uuid,
                environment=self.scan_environment,
            )
            commons.append(vulnerable_path)

        print(
            f"Identified {len(non_commons)} non-commons paths and {len(commons)} commons paths. Storing to DB."
        )

        if len(non_commons) == 0:
            VulnerablePaths(
                repository_id=self.repository_id,
                project_name=self.project.name,
                path=[],
                action_item=None,
                vulnerable_package_id=None,
                has_commons_in_path=False,
                wasp_uuid=self.wasp_uuid,
                environment=self.scan_environment,
            ).save()
        else:
            VulnerablePaths.objects.bulk_create(non_commons)

        if len(commons) == 0:
            VulnerablePaths(
                repository_id=self.repository_id,
                project_name=self.project.name,
                path=[],
                action_item=None,
                vulnerable_package_id=None,
                has_commons_in_path=True,
                wasp_uuid=self.wasp_uuid,
                environment=self.scan_environment,
            ).save()
        else:
            VulnerablePaths.objects.bulk_create(commons)

        print("Store to DB complete.")
