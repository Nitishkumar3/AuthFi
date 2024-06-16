import dns.resolver

def CheckTXTRecord(Domain, Key):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1']
        
        answers = resolver.resolve(Domain, 'TXT')
        txtrecords = [txtrecord.decode('utf-8') for rdata in answers for txtrecord in rdata.strings]
        if Key in txtrecords:
            return True
        else:
            return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.Timeout:
        return False
    except Exception as e:
        return False

domain = "techmedok.com"
Key = "O5Gk0qQ07F0tLrDg"
print(CheckTXTRecord(domain, Key))