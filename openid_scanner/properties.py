def add_list(scan_properties, key, value):
    if key not in scan_properties or scan_properties[key] is None:
        scan_properties[key] = [value]
    else:
        scan_properties[key].append(value)


def add_kv(scan_properties, parent_key, key, value):
    if parent_key not in scan_properties or scan_properties[parent_key] is None:
        scan_properties[parent_key] = {key: value}
    else:
        scan_properties[parent_key][key] = value
