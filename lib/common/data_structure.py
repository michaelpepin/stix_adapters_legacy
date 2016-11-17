

def gen_cybox_struc():
    _version_ = '2.1.0.12'
    return{
        'cybox': {
            'core': {
                'observable': {
                    'Observable': {
                        'id': None,
                        'title': None,
                        'description': None,
                        'object': None,
                        'event': None,
                        'observable_composition': None,
                        'idref': None,
                        'sighting_count': None,
                        'observable_source': [],
                        'keywords': None,
                        'pattern_fidelity': None
                    }
                }
            },
            'objects': {
                'address_object': {
                    'Address': {
                        'Address_Value': None,
                        'category': None,
                        'is_destination': None,
                        'is_source': None,
                        'is_spoofed': None,
                        'VLAN_Name': None,
                        'VLAN_Num': None,
                    }
                }
            }
        }
    }

def gen_stix_dict_structure():
    _version_ = '1.2.0.0'
    from stix.extensions.marking.terms_of_use_marking import TermsOfUseMarkingStructure

    return {
        'stix': {
            'extensions': {
                'marking': {
                    'terms_of_use_marking': {
                        'TermsOfUseMarkingStructure': {
                            'terms_of_use': None
                        }
                    }
                }

            },
            'common': {
                'identity': {
                    'name': None,
                    'id': None,
                    'idref': None,
                    'related_identities': None
                },
                'information_source': {
                    'description': None,
                    'references': None,
                    'contributing_sources': None,
                    'identity': None,
                    'time': None,
                    'tools': None,
                    'roles': None
                } 
            },
            'data_marking': {
                'markings': [],
                'marking_structure':{
                    'id': None,
                    'idref': None,
                    'marking_model_name': None,
                    'marking_model_ref': None
                }
            },
            'core': {
                'stix_header': {
                    'title': None,
                    'description': None,
                    'short_description': None,
                    'handling': None,
                    'information_source': None,
                    'profiles': None,
                },
                'stix_package':{
                    'version': '1.2.0.0',
                    'timestamp': None,
                    'stix_header': None,

                }
            },
            'indicator': {
                'negate': None,
                'alternative_id': None,
                'indicated_ttps': None,
                'test_mechanisms': None,
                'suggested_coas': None,
                'sightings': None,
                'composite_indicator_expression': None,
                'handling': None,
                'kill_chain_phases': None,
                'related_indicators': None,
                'likely_impact': None,
                'indicator_types': None,
                'confidence': None,
                'valid_time_positions': None,
                'observable': None,
                'producer': None,
                'related_campaigns': None,
                'related_packages': None,
            }
        }
    }




