# Contribution Guidelines

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](code-of-conduct.md). By participating in this project you agree to abide by its terms.

## Adding an awesome search query

Ensure your Issue or Pull Request includes the following information or follows this format:

- Narrow down the results as much as possible using [Shodan's filters](https://danielmiessler.com/study/shodan/)...but not too much, be careful not to exclude people trying to hide via [security by obscurity](https://cwe.mitre.org/data/definitions/656.html)! (Geniuses with SSH listening on port 2222 instead of 22, for example. 🙄)
- Include a link to the search results page with the `→` symbol at the end of the H3 heading. **Copy the EXACT query into the Shodan search box and copy and paste the resulting URL** to make sure it's identical and encoded properly.
- Don't include a `country:` filter. It's okay if a certain technology is only used by a certain country, but there's no need to artifically limit the results to that locale alone. Leave that up to the searcher.
- Screenshots are unnecessary, unless they add something interesting, shocking, or out of the ordinary — like a [billboard for burgers](https://github.com/jakejarvis/awesome-shodan-queries#samsung-electronic-billboards-) or a [ransomware-infected desktop](https://github.com/jakejarvis/awesome-shodan-queries#unprotected-vnc-).
- Descriptions are also unnecessary, unless you have a link you'd like to include to a page with more information, like an [important CVE](https://nvd.nist.gov/vuln/detail/CVE-2017-0144).
- If you have a question, just ask! No stupid questions around here.

## Updating your Pull Request

Sometimes, a maintainer of this list will ask you to edit your Pull Request before it is included. This is normally due to spelling errors or because your PR didn't match the list guidelines above.

[Here](https://github.com/RichardLitt/knowledge/blob/master/github/amending-a-commit-guide.md) is a write up on how to change a Pull Request, and the different ways you can do that.