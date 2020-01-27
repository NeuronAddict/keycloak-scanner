def add_list(scan_properties, key, value):
    if key not in scan_properties or scan_properties[key] is None:
        scan_properties[key] = [value]
    else:
        scan_properties[key].append(value)
