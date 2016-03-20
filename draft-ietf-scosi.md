---
title: Concise Software Identifiers
abbrev: COSWID
docname: draft-ietf-scosi-latest
stand_alone: true
ipr: trust200902
area: Security
wg: tbd
kw: Internet-Draft
cat: info
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: J. Fitzgerald-McKay
  name: Jessica Fitzgerald-McKay
  org: Department of Defense
  abbrev: DOD
  email: jmfitz2@nsa.gov
  street: 9800 Savage Road
  city: Ft. Meade
  region: Maryland
  country: USA
- ins: C. Schmidt
  name: Charles Schmidt
  org: The MITRE Corporation
  abbrev: MITRE
  email: cmschmidt@mitre.org
  street: 202 Burlington Road
  city: Bedford
  region: Maryland
  code: '01730'
  country: USA
- ins: D. Waltermire
  name: David Waltermire
  org: National Institute of Standards and Technology
  abbrev: NIST
  email: david.waltermire@nist.gov
  street: 100 Bureau Drive
  city: Gaithersburg
  region: Maryland
  code: '20877'
  country: USA

normative:
  RFC7049: cbor
  SAM:
    title: >
      Information technology - Software asset management - Part 5: Overview and vocabulary
    date: 2013-11-15
    seriesinfo:
      ISO/IEC: 19770-5:2013
  SWID:
    title: >
      Information technology - Software asset management - Part 2: Software identification tag'
    date: 2015-10-01
    seriesinfo:
      ISO/IEC: 19770-2:2015
  CVE:
    title: >
      Technical Guidance for Handling the New CVE-ID Syntax
    date: 2014-12-12
    seriesinfo:
      The MITRE Corporation

informative:
  RFC3444:
  RFC4949:
  I-D.greevenbosch-appsawg-cbor-cddl: cddl
  I-D.birkholz-tuda: tuda

--- abstract 

This document defines a concise representation of ISO 19770-2:2015 Software Identifiers (SWID tags) that is interoperable with the XML schema definition of ISO 19770-2:2015. 

--- middle

# Introduction

SWID tags have several applications including but not limited to:

* Software Inventory Management, a part of the Software Asset Management (SAM) process {{SAM}}, which requires an accurate list of discernible deployed software instances.

* Vulnerability Assessment, which requires a semantic link between standardized vulnerability descriptions and IT-assets.

* Remote Attestation, which requires a link between golden (well-known) measurements and software instances.

SWID tags, as defined in ISO-19770-2:2015 {{SWID}}, provide a standardized format for a record that identifies and describes a specific release of a software product. Different software products, and even different releases of a particular software product, each have a different SWID tag record associated with them. In addition to defining the format of these records, ISO-19770-2:2015 defines requirements concerning the SWID tag lifecycle. Specifically, when a software product is installed on an endpoint, that product's SWID tag is also installed. Likewise, when the product is uninstalled or replaced, the SWID tag is deleted or replaced, as appropriate. As a result, ISO-19770-2:2015 describes a system wherin there is a correspondence between the set of installed software products on an endpoint, and the presence on that endpoint of the SWID tags corresponding to those products.

SWID tags are meant to be flexible and able to express a broad set of metadata about a software product. Moreover, there are multiple types of SWID tags, each providing different types of information. For example, a "media tag" is used to describe an application's installation image on an installation media, while a "patch tag" is meant to describe a patch that modifies some other application. Therefore, the complete set of attributes or types of information elements that can be included in a SWID tag often exceeds the scope a single application of SWID.

This document defines a more concise representation of SWID tags in the Concise Binary Object Representation (CBOR) {{-cbor}}.  This is described via the CBOR Data Definition Language (CDDL) {{-cddl}}.  The resulting Concise SWID data definition is interoperable with the XML schema definition of ISO-19770-2:2015 {{SWID}}. The vocabulary, i.e., the CDDL names of the types and members used in the Concise SWID data definition are mapped to more concise labels represented as small integers. The names used in the CDDL and the mapping to the CBOR representation using integer labels is based on the vocabulary of the attribute and element names defined in ISO-19770-2:2015.

In essence, XML SWID tags are not small, and the use of SWID tags in applications can cause a large amount of data to be transported, larger than may be acceptable for constrained devices. Concise SWID tags reduce the amount of data transported by using CBOR and maps human-readable labels of that content to more concise Integer labels (indices).

# Concise SWID data definition

This is a complete representation of the content of the ISO-19770-2:2015 {{SID}} XML schema definition in CDDL. This representation includes all SWID tag fields and thus supports all SWID tag use cases. The CamelCase notation used in the XML schema definition is changed to hyphen-separated notation (e.g. ResourceCollection is named resource-collection in the Concise SWID data definition). The human-readable names of array members are mapped to integer indices via a block of rules at the bottom of the Concise SWID data definition. 48 character strings of the SWID vocabulary that would have to be stored or transported in full if using the original vocabulary are replaced.

~~~ CDDL

software-identity = {
  global-attr,
  ? content,
  ? corpus,
  ? patch,
  ? media,
  name,
  ? supplemental,
  tag-id,
  ? tag-version,
  ? version,
  ? version-scheme,
}

NMTOKEN = text            ; .regexp to add some validation?
NMTOKENS = [* NMTOKEN]

any-attr = text
any-element = any

date-time = time
any-uri = uri

global-attr = (
  * (text => any-attr),
  ? lang,
)

meta-type = (
  global-attr,
  * (text => any-attr),
)

meta-element = [
  global-attr,
  * (text => any-attr),
]

resource-collection = (
  global-attr,
  * (directory-entry // file-entry // process-entry // resource-entry)
)

file = {
  filesystem-item,
  ? size,
  ? version,
  * (text => any-attr),
}

filesystem-item = (
  meta-type,
  ? key,
  ? location,
  name,
  ? root,
)

directory = {
  filesystem-item,
  path-elements,
}

process = {
  global-attr,
  name,
  ? pid,
}

resource = {
  global-attr,
  type,
}

entity = {
  global-attr,
  meta-elements,
  name,
  ? reg-id,
  role,
  ? thumbprint,
}

evidence = {
  global-attr,
  resource-collection,
  ? date,
  ? device-id,
}

link = {
  global-attr,
  ? artifact,
  href,
  ? media,
  ? ownership,
  rel,
  ? type,
  ? use,
}

software-meta = {
  global-attr,
  ? activation-status,
  ? channel-type,
  ? colloquial-version,
  ? description,
  ? edition,
  ? entitlement-data-required,
  ? entitlement-key,
  ? generator,
  ? persistent-id,
  ? product,
  ? product-family,
  ? revision,
  ? summary,
  ? unspsc-code,
  ? unspsc-version,
}

payload = {
  global-attr,
  resource-collection,
}

tag-id = (0: text)
name = (1: text)
content = (2: [* entity / evidence / link / software-meta / payload / any-element])
corpus = (3: bool)
patch = (4: bool)
media = (5: text)
supplemental = (6: bool)
tag-version = (7: integer)
version = (8: text)
version-scheme = (9: NMTOKEN)
lang = (10: text)
directory-entry = (11: directory)
file-entry = (12: file)
process-entry = (13: process)
resource-entry = (14: resource)
size = (15: integer)
key = (16: bool)
location = (17: text)
root = (18: text)
path-elements = (19: ([* (directory / file)]))
pid = (20: integer)
type = (21: text)
meta-elements = (22: ([* meta-element]))
reg-id = (23: any-uri)
role = (24: NMTOKENS)
thumbprint = (25: text)
date = (26: date-time)
device-id = (27: text)
artifact = (28: text)
href = (29: any-uri)
ownership = (30: ("shared" / "private" / "abandon"))
rel = (31: NMTOKEN)
use = (32: ("optional" / "required" / "recommended"))
activation-status = (33: text)
channel-type = (34: text)
colloquial-version = (35: text)
description = (36: text)
edition = (37: text)
entitlement-data-required = (38: bool)
entitlement-key = (39: text)
generator = (40: text)
persistent-id = (41: text)
product = (42: text)
product-family = (43: text)
revision = (44: text)
summary = (45: text)
unspsc-code = (46: text)
unspsc-version = (47: text)

~~~

# COSE signatures for Concise SWID tags

Concise SWID tags require a different signature scheme than the ISO SWID tags represented via the XML schema definition. COSE provides the required mechanism, which will result in additional attributes to be included in the general Concise SWID data definition, e.g. signature-type ("compat", "cose", etc.).

#  IANA considerations

This document will include requests to IANA: Integer indices for SWID content attributes and information elements.

#  Security Considerations

TODO There are: validation, denial of service, counterfeit, etc.

#  Acknowledgements

#  Change Log

First version -00

# Contributors

--- back

<!--  LocalWords:  SWID verifier TPM filesystem
 -->
