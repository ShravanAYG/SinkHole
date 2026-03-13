#!/bin/bash

curl -X POST 'https://api.firecrawl.dev/v2/scrape' -H 'Authorization: Bearer fc-8e30886228db498795f43e2f1d25b59f' -H 'Content-Type: application/json' -d $'{
  "url": "http://hacksinkhole.duckdns.org/"
}'

