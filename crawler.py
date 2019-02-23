def extract_links(parsed_url, doc, domains):
    page_links = []
    page_links += doc.xpath(".//*/@href")
    page_links += doc.xpath(".//*/@src")
    page_links += doc.xpath(".//*/@action")

    links = set()
    params = set()
    param_vars = list()

    for link in page_links:
        tmp = link.split('?')
        if len(tmp) > 1:
            params.add(tmp[1])
            
        main_part = tmp[0]
        main_part = main_part.strip().split('#')[0]
    
        if main_part.split('.')[-1] not in content_ext:
            if main_part.startswith('http') == False:
                if main_part.startswith('//'):
                    main_part = "".join((parsed_url.scheme,'://', main_part[2:]))
                else:
                    if main_part.startswith('/'):
                        main_part = "".join((parsed_url.scheme,'://', parsed_url.netloc, main_part))

            for domain in domains:
                if main_part.find(domain) != -1:
                    links.add(main_part)

        for p in list(params):
            tmp = p.split('&')
            for i in tmp:
                param_vars.append(i.split('=')[0])

    return links, param_vars  