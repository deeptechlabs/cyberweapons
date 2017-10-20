
CLASSIFICATION_DEFINITION_TEMPLATE = {
    # This is a demonstration classification definition to showcase all the
    # different features of the classification engine

    # Classification level where a smaller number is lower
    # classification then higher number.
    "levels": [
        # List of classification level items
        {
            # Long name of the classification item
            "name": "UNRESTRICTED",
            # Classification level (higher is more classified)
            "lvl": 100,
            # Short name of the classification level
            "short_name": "U",
            # Any aliases that this level can have
            "aliases": [],
            # Description of the classification level
            "description": "No restrictions applied to data.",
            # Stylesheet applied in the UI for the different levels
            "css": {
                # Top banner stylesheet (alert-* because it's based of bootstrap alert dialogs)
                "banner": "alert-default",
                # Label stylesheet (label-* because it's based of bootstrap label components)
                "label": "label-default",
                # Text stylesheet (text-* because it's based of bootstrap text color styles)
                "text": "text-muted"
            }
        },
        {
            "name": "RESTRICTED",
            "lvl": 200,
            "short_name": "R",
            "aliases": ["CLASSIFIED", "DO NOT LOOK"],
            "description": "Data restricted to a certain few...",
            "css": {
                "banner": "alert-info",
                "label": "label-primary",
                "text": "text-primary"
            }
        }
    ],
    # A user requesting access to an item must
    # have all the required tokens the item has to gain
    # access to this item
    "required": [
        # List of required tokens
        {
            # Long display name for the token
            "name": "SUPER USER",
            # Short display name for the token
            "short_name": "SU",
            # Any aliases this token can have
            "aliases": [],
            # Description of the required token
            "description": "Gotta be a super user to see this!",
            # The minimum classification level an item must have
            # for this token to be valid. (optional)
            "require_lvl": 200
        },
        {
            "name": "ADMIN",
            "short_name": "ADM",
            "aliases": ["GOD"],
            "description": "Gotta be an administrator to see this!"
        }
    ],
    # A user requesting access to an item must
    # must be part of a least of one the group
    # the item is part of to gain access
    "groups": [
        # List of possible groups
        {
            # Long display name for the group
            "name": "DEPARTMENT 1",
            # Short display name for the group
            "short_name": "D1",
            # Any aliases this group can have
            "aliases": ["DEPTS", "ANY"],
            # Description of the group
            "description": "Users of department 1.",
            # This is a special flag that when set to true, if any groups are selected
            # in a classification. This group will automatically be selected too. (optional)
            "auto_select": True,
            # Assuming that this groups is the only group selected, this is the display name
            # that will be used in the classification (that values has to be in the aliases
            # of this group and only this group) (optional)
            "solitary_display_name": "ANY"
        },
        {
            "name": "DEPARTMENT 2",
            "short_name": "D2",
            "aliases": ["DEPTS"],
            "description": "Users of department 2.",
        },
    ],
    # A user requesting access to an item must
    # must be part of a least of one the group
    # the item is part of to gain access
    "subgroups": [
        # List of possible subgroups
        {
            # Long display name for the subgroup
            "name": "GROUP 1",
            # Short display name for the subgroup
            "short_name": "G1",
            # Any aliases this subgroup can have
            "aliases": [],
            # Description of the subgroup
            "description": "Users of group 1 (which are part of deparment 1).",
            # This is a special flag that when enabled, if this subgroup is selected
            # this will also automatically select the corresponding group (optional)
            "require_group": "D1",
            # This is a special flag that when enabled, if this subgroup is selected
            # this will make sure that none other then the corresponding group is
            # selected (optional)
            "limited_to_group": "D1"
        },
        {
            "name": "GROUP 2",
            "short_name": "G2",
            "aliases": [],
            "description": "Users of group 2 (can be part of any department).",
        },
    ],
    # Default unrestricted classification
    "unrestricted": "U",
    # Default restricted classification
    "restricted": "R//GOD//REL TO D1",
    # By turning this flag off, this will completely disable the classification engine
    "enforce": True
}


class InvalidClassification(Exception):
    pass


class InvalidDefinition(Exception):
    pass


class Classification(object):
    MAX_LVL = 10000
    INVALID_LVL = 10001

    def __init__(self, classification_definition=None):
        """
        Returns the classification class instantiated with the classification_definition

        Args:
            classification_definition:  The classification definition dictionary,
                                        see DEFAULT_CLASSIFICATION_DEFINITION for an example.
        """
        banned_params_keys = ['name', 'short_name', 'lvl', 'aliases', 'auto_select', 'css', 'description']
        self.levels_map = {}
        self.levels_map_stl = {}
        self.levels_map_lts = {}
        self.levels_styles_map = {}
        self.levels_aliases = {}
        self.access_req_map_lts = {}
        self.access_req_map_stl = {}
        self.access_req_aliases = {}
        self.groups_map_lts = {}
        self.groups_map_stl = {}
        self.groups_aliases = {}
        self.groups_auto_select = []
        self.subgroups_map_lts = {}
        self.subgroups_map_stl = {}
        self.subgroups_aliases = {}
        self.subgroups_auto_select = []
        self.params_map = {}
        self.description = {}

        if classification_definition is None:
            classification_definition = CLASSIFICATION_DEFINITION_TEMPLATE
        try:
            self.enforce = classification_definition['enforce']

            for x in classification_definition['levels']:
                short_name = x['short_name'].upper()
                name = x['name'].upper()

                if short_name == "INV" or name == "INVALID":
                    raise InvalidDefinition("You cannot use INVALID or INV in your classification definition. "
                                            "This is a reserved word")

                lvl = x['lvl']
                if lvl > self.MAX_LVL:
                    raise InvalidDefinition("Level over maximum classification level of %s." % self.MAX_LVL)
                self.levels_map[short_name] = lvl
                self.levels_map[lvl] = short_name
                self.levels_map_stl[short_name] = name
                self.levels_map_lts[name] = short_name
                for a in x.get('aliases', []):
                    self.levels_aliases[a.upper()] = short_name
                self.params_map[short_name] = {k: v for k, v in x.iteritems() if k not in banned_params_keys}
                self.params_map[name] = self.params_map[short_name]
                self.levels_styles_map[short_name] = x.get('css', {'banner': 'alert-default',
                                                                   'label': 'label-default',
                                                                   'text': 'text-muted'})
                self.levels_styles_map[name] = self.levels_styles_map[short_name]
                self.description[short_name] = x.get('description', "N/A")
                self.description[name] = self.description[short_name]

            # Add Invalid classification
            self.levels_map["INV"] = self.INVALID_LVL
            self.levels_map[self.INVALID_LVL] = "INV"
            self.levels_map_stl["INV"] = "INVALID"
            self.levels_map_lts["INVALID"] = "INV"

            for x in classification_definition['required']:
                short_name = x['short_name'].upper()
                name = x['name'].upper()
                self.access_req_map_lts[name] = short_name
                self.access_req_map_stl[short_name] = name
                for a in x.get('aliases', []):
                    self.access_req_aliases[a.upper()] = self.access_req_aliases.get(a.upper(), []) + [short_name]
                self.params_map[short_name] = {k: v for k, v in x.iteritems() if k not in banned_params_keys}
                self.params_map[name] = self.params_map[short_name]
                self.description[short_name] = x.get('description', "N/A")
                self.description[name] = self.description[short_name]

            for x in classification_definition['groups']:
                short_name = x['short_name'].upper()
                name = x['name'].upper()
                self.groups_map_lts[name] = short_name
                self.groups_map_stl[short_name] = name
                for a in x.get('aliases', []):
                    self.groups_aliases[a.upper()] = self.groups_aliases.get(a.upper(), []) + [short_name]
                if x.get('auto_select', False):
                    self.groups_auto_select.append(short_name)
                self.params_map[short_name] = {k: v for k, v in x.iteritems() if k not in banned_params_keys}
                self.params_map[name] = self.params_map[short_name]
                self.description[short_name] = x.get('description', "N/A")
                self.description[name] = self.description[short_name]

            for x in classification_definition['subgroups']:
                short_name = x['short_name'].upper()
                name = x['name'].upper()
                self.subgroups_map_lts[name] = short_name
                self.subgroups_map_stl[short_name] = name
                for a in x.get('aliases', []):
                    self.subgroups_aliases[a.upper()] = self.subgroups_aliases.get(a.upper(), []) + [short_name]
                if x.get('auto_select', False):
                    self.subgroups_auto_select.append(short_name)
                self.params_map[short_name] = {k: v for k, v in x.iteritems() if k not in banned_params_keys}
                self.params_map[name] = self.params_map[short_name]
                self.description[short_name] = x.get('description', "N/A")
                self.description[name] = self.description[short_name]

            if not self.is_valid(classification_definition['unrestricted']):
                raise Exception("Classification definition's unrestricted classification is invalid.")

            if not self.is_valid(classification_definition['restricted']):
                raise Exception("Classification definition's restricted classification is invalid.")

            self.UNRESTRICTED = classification_definition['unrestricted']
            self.RESTRICTED = classification_definition['restricted']

            self.UNRESTRICTED = self.normalize_classification(classification_definition['unrestricted'])
            self.RESTRICTED = self.normalize_classification(classification_definition['restricted'])

            self.INVALID_CLASSIFICATION = "INVALID"

        except Exception as e:
            raise Exception("Failed to initialize classification engine. "
                            "Your classification definition as issues. [%s]" % str(e))

    ############################
    # Private functions
    ############################
    def _get_c12n_level_index(self, c12n):
        # Parse classifications in uppercase mode only
        c12n = c12n.upper()

        lvl = c12n.split("//")[0]
        if lvl in self.levels_map:
            return self.levels_map[lvl]
        elif lvl in self.levels_map_lts:
            return self.levels_map[self.levels_map_lts[lvl]]
        elif lvl in self.levels_aliases:
            return self.levels_map[self.levels_aliases[lvl]]
        else:
            raise InvalidClassification("Classification level '%s' was not found in "
                                        "your classification definition." % lvl)

    def _get_c12n_level_text(self, lvl_idx, long_format=True):
        text = self.levels_map.get(lvl_idx, None)
        if not text:
            raise InvalidClassification("Classification level number '%s' was not "
                                        "found in your classification definition." % lvl_idx)
        if long_format:
            return self.levels_map_stl[text]
        return text

    def _get_c12n_required(self, c12n, long_format=True):
        # Parse classifications in uppercase mode only
        c12n = c12n.upper()

        return_set = set()
        part_set = set(c12n.split("/"))

        for p in part_set:
            if p in self.access_req_map_lts:
                return_set.add(self.access_req_map_lts[p])
            elif p in self.access_req_map_stl:
                return_set.add(p)
            elif p in self.access_req_aliases:
                for a in self.access_req_aliases[p]:
                    return_set.add(a)

        if long_format:
            return sorted([self.access_req_map_stl[r] for r in return_set])
        return sorted(list(return_set))

    def _get_c12n_groups(self, c12n, long_format=True):
        # Parse classifications in uppercase mode only
        c12n = c12n.upper()

        g1_set = set()
        g2_set = set()

        grp_part = c12n.split("//")
        groups = []
        for gp in grp_part:
            gp = gp.replace("REL TO ", "")
            temp_group = set([x.strip() for x in gp.split(",")])
            for t in temp_group:
                groups.extend(t.split("/"))

        for g in groups:
            if g in self.groups_map_lts:
                g1_set.add(self.groups_map_lts[g])
            elif g in self.groups_map_stl:
                g1_set.add(g)
            elif g in self.groups_aliases:
                for a in self.groups_aliases[g]:
                    g1_set.add(a)
            elif g in self.subgroups_map_lts:
                g2_set.add(self.subgroups_map_lts[g])
            elif g in self.subgroups_map_stl:
                g2_set.add(g)
            elif g in self.subgroups_aliases:
                for a in self.subgroups_aliases[g]:
                    g2_set.add(a)

        if long_format:
            return sorted([self.groups_map_stl[r] for r in g1_set]), sorted([self.subgroups_map_stl[r] for r in g2_set])
        return sorted(list(g1_set)), sorted(list(g2_set))

    @staticmethod
    def _can_see_required(user_req, req):
        return set(req).issubset(user_req)

    @staticmethod
    def _can_see_groups(user_groups, req):
        if len(req) == 0:
            return True

        for g in user_groups:
            if g in req:
                return True

        return False

    # noinspection PyTypeChecker
    def _get_normalized_classification_text(self, lvl_idx, req, groups, subgroups, long_format=True,
                                            skip_auto_select=False):
        # 1. Check for all required items if they need a specific classification lvl
        required_lvl_idx = 0
        for r in req:
            required_lvl_idx = max(required_lvl_idx, self.params_map.get(r, {}).get("require_lvl", 0))
        out = self._get_c12n_level_text(max(lvl_idx, required_lvl_idx), long_format=long_format)

        # 2. Check for all required items if they should be shown inside the groups display part
        req_grp = []
        for r in req:
            if self.params_map.get(r, {}).get('is_required_group'):
                req_grp.append(r)
        req = list(set(req).difference(set(req_grp)))

        if req:
            out += "//" + "/".join(req)
        if req_grp:
            out += "//" + "/".join(sorted(req_grp))

        # 3. Add auto-selected subgroups
        if len(subgroups) > 0 and len(self.subgroups_auto_select) > 0 and not skip_auto_select:
            subgroups = sorted(list(set(subgroups).union(set(self.subgroups_auto_select))))

        # 4. For every subgroup, check if the subgroup requires or is limmited to a specific group
        for sg in subgroups:
            required_group = self.params_map.get(sg, {}).get("require_group", None)
            if required_group is not None:
                groups.append(required_group)

            limited_to_group = self.params_map.get(sg, {}).get("limited_to_group", None)
            if limited_to_group is not None:
                if limited_to_group in groups:
                    groups = [limited_to_group]
                else:
                    groups = []

        # 5. Add auto-selected groups
        if len(groups) > 0 and len(self.groups_auto_select) > 0 and not skip_auto_select:
            groups = sorted(list(set(groups).union(set(self.groups_auto_select))))

        if groups:
            out += {True: "/", False: "//"}[len(req_grp) > 0]
            if len(groups) == 1:
                # 6. If only one group, check if it has a solitary display name.
                grp = groups[0]
                display_name = self.params_map.get(grp, {}).get('solitary_display_name', grp)
                if display_name != grp:
                    out += display_name
                else:
                    out += "REL TO " + grp
            else:
                if not long_format:
                    # 7. In short format mode, check if there is an alias that can replace multiple groups
                    for alias, values in self.groups_aliases.iteritems():
                        if len(values) > 1:
                            if sorted(values) == groups:
                                groups = [alias]
                out += "REL TO " + ", ".join(sorted(groups))

        if subgroups:
            if len(groups) > 0 or len(req_grp) > 0:
                out += "/"
            else:
                out += "//"
            out += "/".join(sorted(subgroups))

        return out

    def _get_classification_parts(self, c12n, long_format=True):
        lvl_idx = self._get_c12n_level_index(c12n)
        req = self._get_c12n_required(c12n, long_format=long_format)
        groups, subgroups = self._get_c12n_groups(c12n, long_format=long_format)

        return lvl_idx, req, groups, subgroups

    @staticmethod
    def _max_groups(groups_1, groups_2):
        if len(groups_1) > 0 and len(groups_2) > 0:
            groups = set(groups_1) & set(groups_2)
        else:
            groups = set(groups_1) | set(groups_2)

        if len(groups_1) > 0 and len(groups_2) > 0 and len(groups) == 0:
            # NOTE: Intersection generated nothing, we will raise an InavlidClassification exception
            raise InvalidClassification("Could not find any intersection between the groups")

        return list(groups)

    # ++++++++++++++++++++++++
    # Public functions
    # ++++++++++++++++++++++++
    # noinspection PyUnusedLocal
    def default_user_classification(self, user=None, long_format=True):
        """
        You can overload this function to specify a way to get the default classification of a user.
        By default, this function returns the UNRESTRICTED value of your classification definition.

        Args:
            user: Which user to get the classification for
            long_format: Request a long classification format or not

        Returns:
            The classification in the specified format
        """
        return self.UNRESTRICTED

    def get_parsed_classification_definition(self):
        """
        Returns all dictionary of all the variables inside the classification object that will be used
        to enforce classification throughout the system.
        """
        from copy import deepcopy
        out = deepcopy(self.__dict__)
        del out['levels_map']["INV"]
        del out['levels_map'][self.INVALID_LVL]
        del out['levels_map_stl']["INV"]
        del out['levels_map_lts']["INVALID"]
        return out

    def get_access_control_parts(self, c12n, user_classification=False):
        """
        Returns a dictionary containing the different access parameters SOLR needs to build it's queries

        Args:
            c12n: The classification to get the parts from
        """
        if not self.enforce:
            c12n = self.UNRESTRICTED

        # Normalize the classification before gathering the parts
        c12n = self.normalize_classification(c12n, skip_auto_select=user_classification)

        access_lvl = self._get_c12n_level_index(c12n)
        access_req = self._get_c12n_required(c12n, long_format=False)
        access_grp1, access_grp2 = self._get_c12n_groups(c12n, long_format=False)

        return {
            '__access_lvl__': access_lvl,
            '__access_req__': access_req,
            '__access_grp1__': access_grp1,
            '__access_grp2__': access_grp2
        }

    def get_access_control_req(self):
        """
        Returns a list of the different possible REQUIRED parts
        """
        if not self.enforce:
            return []

        return self.access_req_map_stl.keys()

    def get_access_control_groups(self):
        """
        Returns a list of the different possible GROUPS
        """
        if not self.enforce:
            return []

        return self.groups_map_stl.keys()

    def get_access_control_subgroups(self):
        """
        Returns a list of the different possible SUBGROUPS
        """
        if not self.enforce:
            return []

        return self.subgroups_map_stl.keys()

    def intersect_user_classification(self, user_c12n_1, user_c12n_2, long_format=True):
        """
        This function intersects two user classification to return the maximum classification
        that both user could see.

        Args:
            user_c12n_1: First user classification
            user_c12n_2: Second user classification
            long_format: True/False in long format

        Returns:
            Intersected classification in the desired format
        """
        if not self.enforce:
            return self.UNRESTRICTED

        # Normalize classifications before comparing them
        if user_c12n_1 is not None:
            user_c12n_1 = self.normalize_classification(user_c12n_1, skip_auto_select=True)
        if user_c12n_2 is not None:
            user_c12n_2 = self.normalize_classification(user_c12n_2, skip_auto_select=True)

        if user_c12n_1 is None:
            return user_c12n_2
        if user_c12n_2 is None:
            return user_c12n_1

        lvl_idx_1, req_1, groups_1, subgroups_1 = self._get_classification_parts(user_c12n_1, long_format=long_format)
        lvl_idx_2, req_2, groups_2, subgroups_2 = self._get_classification_parts(user_c12n_2, long_format=long_format)

        req = list(set(req_1) & set(req_2))
        groups = list(set(groups_1) & set(groups_2))
        subgroups = list(set(subgroups_1) & set(subgroups_2))

        return self._get_normalized_classification_text(min(lvl_idx_1, lvl_idx_2),
                                                        req,
                                                        groups,
                                                        subgroups,
                                                        long_format=long_format,
                                                        skip_auto_select=True)

    def is_accessible(self, user_c12n, c12n):
        """
        Given a user classification, check if a user is allow to see a certain classification

        Args:
            user_c12n: Maximum classification for the user
            c12n: Classification the user which to see

        Returns:
            True is the user can see the classification
        """
        if not self.enforce:
            return True

        if c12n is None:
            return True

        # Normalize classifications before comparing them
        user_c12n = self.normalize_classification(user_c12n, skip_auto_select=True)
        c12n = self.normalize_classification(c12n, skip_auto_select=True)

        user_req = self._get_c12n_required(user_c12n)
        user_groups, user_subgroups = self._get_c12n_groups(user_c12n)
        req = self._get_c12n_required(c12n)
        groups, subgroups = self._get_c12n_groups(c12n)

        if self._get_c12n_level_index(user_c12n) >= self._get_c12n_level_index(c12n):
            if not self._can_see_required(user_req, req):
                return False
            if not self._can_see_groups(user_groups, groups):
                return False
            if not self._can_see_groups(user_subgroups, subgroups):
                return False
            return True
        return False

    def is_valid(self, c12n, skip_auto_select=False):
        """
        Performs a series of checks againts a classification to make sure it is valid in it's current form

        Args:
            c12n: The classification we want to validate

        Returns:
            True if the classification is valid
        """
        if not self.enforce:
            return True

        try:
            # Classification normalization test
            n_c12n = self.normalize_classification(c12n, skip_auto_select=skip_auto_select)
            n_lvl_idx, n_req, n_groups, n_subgroups = self._get_classification_parts(n_c12n)
            lvl_idx, req, groups, subgroups = self._get_classification_parts(c12n)
        except InvalidClassification:
            return False

        if lvl_idx != n_lvl_idx:
            return False

        if sorted(req) != sorted(n_req):
            return False

        if sorted(groups) != sorted(n_groups):
            return False

        if sorted(subgroups) != sorted(n_subgroups):
            return False

        c12n = c12n.replace("REL TO ", "")
        parts = c12n.split("//")

        # There is a maximum of 3 parts
        if len(parts) > 3:
            return False

        cur_part = parts.pop(0)
        # First parts as to be a classification level part
        if cur_part not in self.levels_aliases.keys() and \
                cur_part not in self.levels_map_lts.keys() and \
                cur_part not in self.levels_map_stl.keys():
            return False

        check_groups = False
        while len(parts) > 0:
            # Can't be two groups sections.
            if check_groups:
                return False

            cur_part = parts.pop(0)
            items = cur_part.split("/")
            comma_idx = None
            for idx, i in enumerate(items):
                if "," in i:
                    comma_idx = idx

            if comma_idx is not None:
                items += [x.strip() for x in items.pop(comma_idx).split(",")]

            for i in items:
                if not check_groups:
                    # If current item not found in access req, we might already be dealing with groups
                    if i not in self.access_req_aliases.keys() and \
                            i not in self.access_req_map_stl.keys() and \
                            i not in self.access_req_map_lts.keys():
                        check_groups = True

                if check_groups:
                    # If not groups. That stuff does not exists...
                    if i not in self.groups_aliases.keys() and \
                            i not in self.groups_map_stl.keys() and \
                            i not in self.groups_map_lts.keys() and \
                            i not in self.subgroups_aliases.keys() and \
                            i not in self.subgroups_map_stl.keys() and \
                            i not in self.subgroups_map_lts.keys():
                        return False

        return True

    def max_classification(self, c12n_1, c12n_2, long_format=True):
        """
        Mixes to classification and returns to most restrictive form for them

        Args:
            c12n_1: First classification
            c12n_2: Second classification
            long_format: True/False in long format

        Returns:
            The most restrictive classification that we could create out of the two
        """
        if not self.enforce:
            return self.UNRESTRICTED

        # Normalize classifications before comparing them
        if c12n_1 is not None:
            c12n_1 = self.normalize_classification(c12n_1)
        if c12n_2 is not None:
            c12n_2 = self.normalize_classification(c12n_2)

        if c12n_1 is None:
            return c12n_2
        if c12n_2 is None:
            return c12n_1

        lvl_idx_1, req_1, groups_1, subgroups_1 = self._get_classification_parts(c12n_1, long_format=long_format)
        lvl_idx_2, req_2, groups_2, subgroups_2 = self._get_classification_parts(c12n_2, long_format=long_format)

        req = list(set(req_1) | set(req_2))
        try:
            groups = self._max_groups(groups_1, groups_2)
            subgroups = self._max_groups(subgroups_1, subgroups_2)
        except InvalidClassification:
            return self.INVALID_CLASSIFICATION

        return self._get_normalized_classification_text(max(lvl_idx_1, lvl_idx_2),
                                                        req,
                                                        groups,
                                                        subgroups,
                                                        long_format=long_format)

    def min_classification(self, c12n_1, c12n_2, long_format=True):
        """
        Mixes to classification and returns to least restrictive form for them

        Args:
            c12n_1: First classification
            c12n_2: Second classification
            long_format: True/False in long format

        Returns:
            The least restrictive classification that we could create out of the two
        """
        if not self.enforce:
            return self.UNRESTRICTED

        # Normalize classifications before comparing them
        if c12n_1 is not None:
            c12n_1 = self.normalize_classification(c12n_1)
        if c12n_2 is not None:
            c12n_2 = self.normalize_classification(c12n_2)

        if c12n_1 is None:
            return c12n_2
        if c12n_2 is None:
            return c12n_1

        lvl_idx_1, req_1, groups_1, subgroups_1 = self._get_classification_parts(c12n_1, long_format=long_format)
        lvl_idx_2, req_2, groups_2, subgroups_2 = self._get_classification_parts(c12n_2, long_format=long_format)

        req = list(set(req_1) & set(req_2))
        if len(groups_1) > 0 and len(groups_2) > 0:
            groups = list(set(groups_1) | set(groups_2))
        else:
            groups = []

        if len(subgroups_1) > 0 and len(subgroups_2) > 0:
            subgroups = list(set(subgroups_1) | set(subgroups_2))
        else:
            subgroups = []

        return self._get_normalized_classification_text(min(lvl_idx_1, lvl_idx_2),
                                                        req,
                                                        groups,
                                                        subgroups,
                                                        long_format=long_format)

    def normalize_classification(self, c12n, long_format=True, skip_auto_select=False):
        """
        Normalize a given classification by applying the rules defined in the classification definition.
        This function will remove any invalid parts and add missing parts to the classification.
        It will also ensure that the display of the classification is always done the same way

        Args:
            c12n: Classification to normalize
            long_format: True/False in long format
            skip_auto_select: True/False skip group auto adding, use True when dealing with user's classifications

        Returns:
            A normalized version of the original classification
        """
        if not self.enforce:
            return self.UNRESTRICTED

        lvl_idx, req, groups, subgroups = self._get_classification_parts(c12n, long_format=long_format)
        return self._get_normalized_classification_text(lvl_idx, req, groups, subgroups,
                                                        long_format=long_format,
                                                        skip_auto_select=skip_auto_select)


if __name__ == "__main__":
    import json
    from assemblyline.al.common import forge
    config = forge.get_config(static_seed="assemblyline.al.install.seeds.assemblyline_appliance.seed")
    c = Classification(config.system.classification.definition)
    print json.dumps(c.get_parsed_classification_definition(), indent=4)
