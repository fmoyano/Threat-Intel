from threatintel.models import IOC, IOCType

def deduplicate_iocs(iocs: list[IOC]) -> list[IOC]:
    
    iocs_dict = {}

    for ioc in iocs:
        key = (ioc.type, ioc.value)
        ioc_with_same_key = iocs_dict.get(key, None)
        if ioc_with_same_key:
            ioc_with_same_key.sources.update(ioc.sources)
        else:
            iocs_dict[key] = IOC(ioc.type, ioc.value, set(ioc.sources))

    return list(iocs_dict.values())


print(deduplicate_iocs([
    IOC(IOCType.DOMAIN, "evil.com", {"feed_a"}),
    IOC(IOCType.IP, "203.0.113.42", {"feed_a"}),
    IOC(IOCType.DOMAIN, "evil.com", {"feed_b"}),
]))

ioc1 = IOC(
    IOCType.DOMAIN,
    "evil.com",
    {"feed_a"},
)

ioc2 = IOC(
    IOCType.DOMAIN,
    "evil.com",
    {"feed_b"},
)

iocs = [ioc1, ioc2]

result = deduplicate_iocs(iocs)

print(result)
print(ioc1)