class IVSSSampleGroups:
    impact_group = {
        "Confidentiality": 0.0,
        "Integrity": 0.0,
        "Availability": 0.0
    }

    exposure_group = {
        "Authentication": 0.0,
        "Non-Repudiation": 0.0,
        "Access": 0.0,
        "Complexity": 0.0,
        "Safety": 0.0,
    }

    weights = {
        "Confidentiality": 1.0,
        "Integrity": 1.0,
        "Availability": 1.0,
        "Authentication": 1.0,
        "Non-Repudiation": 1.0,
        "Access": 1.0,
        "Complexity": 1.0,
        "Safety": 1.0,
    }

class IVSSStringVectorUtil:
    abbreviations = {
        "Confidentiality": "C",
        "Integrity": "I",
        "Availability": "A",
        "Authentication": "AU",
        "Non-Repudiation": "NR",
        "Access": "AC",
        "Complexity": "CX",
        "Safety": "S"
    }

    cvss_conversion_map = {
        "C": {
            "N": ("C", "X"),
            "L": ("C", "L"),
            "H": ("C", "H")
        },
        "I": {
            "N": ("I", "X"),
            "L": ("I", "L"),
            "H": ("I", "H")
        },
        "A": {
            "N": ("A", "X"),
            "L": ("A", "L"),
            "H": ("A", "H")
        },
        "VC": { # CVSS 4.0 equivalents to C, I, A.
            "N": ("C", "X"),
            "L": ("C", "L"),
            "H": ("C", "H")
        },
        "VI": {
            "N": ("I", "X"),
            "L": ("I", "L"),
            "H": ("I", "H")
        },
        "VA": {
            "N": ("A", "X"),
            "L": ("A", "L"),
            "H": ("A", "H")
        },
        "AV": {
            "P": ("AC", "L"),
            "L": ("AC", "M"),
            "A": ("AC", "H"),
            "N": ("AC", "VH")
        },
        "AC": { # Manually coded exceptions, since both the Attack Complexity, Privileges Required, and Attack Requirements (in CVSS 4.0) map to Complexity in IVSS.
            "L": ("CX", 2),
            "H": ("CX", 1)
        },
        "PR": { # Read above ^
            "N": ("CX", 2),
            "L": ("CX", 1),
            "H": ("CX", 0)
        },
        "AT": { # Read above ^
            "N": ("CX", 1),
            "P": ("CX", 0)
        },
        "UI": {
            "A": ("AU", "X"),
            "P": ("AU", "L"),
            "N": ("AU", "H")
        },
        "S": {
            "U": ("S", "X"), # In CVSS 3.1, "S" is used for Scope, which is unrelated to safety. It uses the string values "(U)nchanged"...
            "C": ("S", "X"), # ...and "(C)hanged"
            "X": ("S", "X"),
            "N": ("S", "M"),
            "P": ("S", "VH")
        }
    }

    @staticmethod
    def string(value:float, truncated:bool = True) -> str:
        v = round(value)
        if v == 0:
            return "X" if truncated else "Safe"
        if v < 2:
            return "VL" if truncated else "Very Low"
        if v < 4:
            return "L" if truncated else "Low"
        if v < 7:
            return "M" if truncated else "Medium"
        if v <= 9:
            return "H" if truncated else "High"
        
        return "VH" if truncated else "Very High"

    @staticmethod
    def from_string(text:str) -> int: # Slightly different values from converting values to string, to better represent CVSS scores in IVSS.
        match text:
            case "X":
                return 0
            case "VL":
                return 2
            case "L":
                return 4
            case "M":
                return 6
            case "H":
                return 8
            case _:
                return 10

    @staticmethod
    def get_abbreviation(cat:str, match_mode:bool=True) -> str:
        # Match Mode = Match from preset dictionary, default operation.
        # Non-Match Mode = Get first two letters, for new/undefined metrics.
        if match_mode:
            return IVSSStringVectorUtil.abbreviations[cat]
        else:
            return cat[:2]

    @staticmethod
    def get_ivss_str(impact_group, exposure_group) -> str:
        ivss_vector_str = "IVSS:1.0/"
        for group in [impact_group.items(), exposure_group.items()]:
            for i,v in group:
                    value_string = IVSSStringVectorUtil.string(v)
                    if value_string == "X": continue
                    ivss_vector_str += IVSSStringVectorUtil.get_abbreviation(i) + f":{value_string}/"
        return ivss_vector_str[:-1] # Removes the last "/" from the string.

    @staticmethod
    def convert_cvss_vector_to_ivss_vector(cvss_vector_string:str) -> str: # The IVSS string is not ordered correctly.
        cvss_categories = cvss_vector_string.split("/")
        ivss_vector_str = "IVSS:1.0/"
        complexity_score = 0

        for v in cvss_categories:
            if v.split(":")[0] == "CVSS":
                continue

            split_cat = v.split(":")
            if not split_cat[0] in IVSSStringVectorUtil.cvss_conversion_map:
                continue

            if split_cat[0] == "AC" or split_cat[0] == "PR" or split_cat[0] == "AT": # These are all of the metrics that correspond to Complexity in IVSS.
                complexity_score += IVSSStringVectorUtil.cvss_conversion_map[split_cat[0]][split_cat[1]][1] # This is an int, to properly handle the interaction between AC, PR, and AT.
                continue

            ivss_mapping = IVSSStringVectorUtil.cvss_conversion_map[split_cat[0]]
            if not split_cat[1] in ivss_mapping:
                continue

            ivss_mapping = ivss_mapping[split_cat[1]] # And this is a tuple of strings!
            if ivss_mapping[1] != "X":
                ivss_vector_str += f"{ivss_mapping[0]}:{ivss_mapping[1]}/"

        insert_str = ""
        #safety_index = ivss_vector_str.find("S")
        #complexity_index = safety_index-1 if safety_index else len(ivss_vector_str)  # We want to insert Complexity before Safety. # I'll leave this as future work
        match complexity_score:
            case 0:
                pass
            case 1:
                insert_str = "CX:L/"
            case 2:
                insert_str = "CX:M/"
            case _:
                insert_str = "CX:VH/"

        #ivss_vector_str = ivss_vector_str[:complexity_index] + insert_str + ivss_vector_str[complexity_index:]
        ivss_vector_str += insert_str
        return ivss_vector_str[:-1]

    @staticmethod
    def convert_cvss_to_ivss(cvss_vector_string:str) -> tuple[dict[str,float], dict[str, float]]:
        impact_group = IVSSSampleGroups.impact_group.copy()
        exposure_group = IVSSSampleGroups.exposure_group.copy()
        ivss_vector_string = IVSSStringVectorUtil.convert_cvss_vector_to_ivss_vector(cvss_vector_string)
        ivss_categories = ivss_vector_string.split("/")

        valid_input = False
        for v in ivss_categories:
            split_cat = v.split(":")
            full_category_name = [i for i,a in IVSSStringVectorUtil.abbreviations.items() if a == split_cat[0]]
            if not full_category_name:
                continue

            full_category_name = full_category_name[0]
            valid_input = True
            if full_category_name and (split_cat[0] == "C" or split_cat[0] == "I" or split_cat[0] == "A"): # We use the abbreviations for faster string comparisons. It doesn't particularly matter, but it's a few less CPU clock cycles!
                impact_group[full_category_name] = IVSSStringVectorUtil.from_string(split_cat[1])
            elif full_category_name:
                exposure_group[full_category_name] = IVSSStringVectorUtil.from_string(split_cat[1])

        if not valid_input: # If there are no valid groups...
            return ({"":0},{"":0}) # ...send an empty input to trip error detection in other functions. This is not good code, but error detection was added in other places to safeguard against edge cases that are no longer possible, so this saves time.
        return (impact_group, exposure_group)

class IVSSCalculator:
    @staticmethod
    def get_group_score(categories:dict[str, float]) -> float:
        categories_values = categories.values()
        maxCat = max(categories_values)

        new_categories = categories.copy()
        del new_categories[max(new_categories, key=new_categories.get)] # type: ignore

        score = min((maxCat+(sum(categories_values)/len(new_categories)))/1.6, 10)
        return round(score, 1)

    @staticmethod
    def calculate_ivss_score(impact:float, exposure:float, safety:float) -> float:
        exposure_modifier = 0.65*exposure/10
        safety_modifier = 0.2*safety/10
        final_score = min(impact/(1.3-exposure_modifier-safety_modifier), 10)
        return round(final_score, 1)

    @staticmethod
    def get_ivss_score(impact_group:dict[str, float], exposure_group:dict[str, float]) -> tuple[float, str]:
        if not "Safety" in exposure_group: # Malformatted input. Returns an empty IVSS score.
            return (0.0, "An error has occurred. Please check your input and try again.")
        
        processed_exposure = exposure_group.copy()
        del processed_exposure["Safety"]

        impact_score = IVSSCalculator.get_group_score(impact_group)
        exposure_score = IVSSCalculator.get_group_score(processed_exposure)

        ivss_score = IVSSCalculator.calculate_ivss_score(impact_score, exposure_score, exposure_group["Safety"])
        ivss_str = IVSSStringVectorUtil.get_ivss_str(impact_group, exposure_group)
        return ivss_score, ivss_str

    @staticmethod
    def apply_ivss_weights(group:dict[str, float], weights:dict[str, float]) -> dict[str, float]:
        weighted_group = group.copy()
        for i,v in group.items():
            weighted_group[i] = v * weights[i]
        return weighted_group

    @staticmethod
    def get_weighted_ivss_score(impact_group:dict[str, float], exposure_group:dict[str, float], weights:dict[str, float]) -> tuple[float, str]:
        weighted_impact_group = IVSSCalculator.apply_ivss_weights(impact_group, weights)
        weighted_exposure_group = IVSSCalculator.apply_ivss_weights(exposure_group, weights)
        return IVSSCalculator.get_ivss_score(weighted_impact_group, weighted_exposure_group)

    @staticmethod
    def get_ivss_score_from_cvss_vector(cvss_vector_string:str) -> tuple[float, str]:
        groups = IVSSStringVectorUtil.convert_cvss_to_ivss(cvss_vector_string)
        if not groups[0] or not groups[1]: # Error in the input. Returns an empty IVSS score.
            return (0.0, "An error has occurred. Please check your input and try again.")
        
        return IVSSCalculator.get_ivss_score(*IVSSStringVectorUtil.convert_cvss_to_ivss(cvss_vector_string))

class IVSSSeveritiesMap:
    mappings = {
    "Confidentiality": {
        "Vulnerability has no impact on information confidentiality.": 0,
        "Vulnerability does not expose sensor data, but may reveal operation information surrounding the device, such as firmware versions.": 3,
        "Vulnerability exposes a limited amount of sensor data, or completely exposes non-essential information.": 5,
        "Vulnerability majorly exposes main sensor data gathered by the device (i.e. camera feed from cameras).": 9,
        "Vulnerability completely exposes all information present on the device.": 10,
    },
    "Integrity": {
        "Vulnerability has no impact on device integrity.": 0,
        "Vulnerability is capable of causing minor changes or destruction of non-essential information.": 2,
        "Vulnerability is capable of causing major changes or destruction of non-essential information.": 3,
        "Vulnerability is capable of causing minor changes or destruction of main sensor data gathered by the device.": 5,
        "Vulnerability is capable of causing major changes or destruction of main sensor data gathered by the device.": 8,
        "Vulnerability is capable of permanently, irreversibly destroying or altering all information present on the device.": 10,
    },
    "Availability": {
        "Vulnerability has no impact on device availability.": 0,
        "Vulnerability momentarily disrupts device availability, or fully disrupts limited (non-essential) parts of the device.": 3,
        "Vulnerability is capable of nearly or completely compromising device availability.": 8,
        "Vulnerability is capable of causing permanent physical damage to the device.": 9,
        "Vulnerability is capable of permanently and irreversibly destroying the device or rendering it completely inoperable.": 10,
    },
    "Authentication": {
        "Attack has no impact on, or makes no use of, authentication.": 0,
        "Attacker is left with partial control of the device or has a limited ability to impersonate it.": 5,
        "Attacker is left with full control of the device or is able to impersonate it, allowing for the device to be used to attack the remainder of the network.": 10,
    },
    "Non-Repudiation": {
        "Vulnerability has no impact on, or makes no use of, non-repudiation.": 0,
        "Attacker is able to partially mask their activity, such as hiding the information that was compromised.": 5,
        "Attacker is able to completely destroy logs and mask their activity, disrupting forensics activities.": 10,
    },
    "Access": {
        "Vulnerability requires physical access to the device.": 2,
        "Vulnerability requires indirect access to a controller device.": 4,
        "Vulnerability can be executed directly, from the local reach of the network (requires some degree of physical proximity).": 6,
        "Vulnerability can be executed remotely from outside the network, but requires logical access to it (previously compromised network).": 8,
        "Vulnerability can be executed directly, remotely from outside the network.": 10,
    },
    "Complexity": {
        "Vulnerability could not be exploited or is unlikely to be exploitable by the defined threat group.": 0,
        "Vulnerability is complex, has extensive additional conditions, and must be performed manually.": 3,
        "Vulnerability is not complex, but must be performed manually.": 6,
        "Vulnerability can be feasibly automated and scripted.": 10,
    },
    "Safety": {
        "Vulnerability poses no risk to the physical health of individuals.": 0,
        "Vulnerability can directly or indirectly result in minor physical injuries to individuals.": 5,
        "Vulnerability can directly or indirectly result in moderate, severe, or maiming physical injuries, as well as death, to individuals.": 10,
    },
}