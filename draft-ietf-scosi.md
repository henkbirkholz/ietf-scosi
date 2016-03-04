---
title: Scalable Concise Software Identifiers
abbrev: SCOSI
docname: draft-ietf-scosi-latest
stand_alone: true
ipr: trust200902
area: Security
wg: tbd
kw: Internet-Draft
cat: info
coding: us-ascii
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

informative:
  RFC3444:
  RFC4949:
  I-D.greevenbosch-appsawg-cbor-cddl: cddl

--- abstract 

This document defines a concise representation of ISO 19770-2/2015 Software Identifiers (SWID tags) that is interoperable with the XML schema definition of ISO 19770-2/2015. Additionally, this document defines application specific profiles (static subsets) of the corresponding vocabulary to enable better scalability in constraint environments.

--- middle

# Introduction (TODO 1st draft, rephrase)

SWID tags have several applications; including but not limited to: Software Inventory Management, a part of the Software Asset Management (SAM) process (TODO REF ISO-19770-5:2013), which requires an accurate list of discernible deployed software instances. Vulnerability Assessment, which requires a semantic link between standardized vulnerability descriptions and IT-assets. Remote Attestation, which benefits from an accompanying list of golden (well-known) measurements about software.

Software Identifier (SWID) tags are meant to be flexible and able to express virtually any type of software and their associated metadata. Therefore, the complete set of attributes or types of information elements that can be included in a Software Identifier tag often exceeds the scope a single application of SWID. Unfortunately, this flexibility also limits the capabilities of validation and can require a significant amount of resources to cope with its consequences.

As a basis, this documents provides a more concise representation of SWID tags in the CBOR {{-cbor}} described via the CDDL {{-cddl}} - the general Concise SWID data definition - that is interoperable with the XML schema definition of ISO-19770-2:2015 (FIXME someone pls have mercy on this sentence and rephrase it). Derived from this basis, the document defines Concise SWID profiles, which are subsets of the general Concise SWID data definition structure that represent (in a standardized way) only information elements that are required in specific applications. The Concise SWID profile defintions can be completely mapped to the XML schema definition of ISO-19770-2:2015 but not vice versa (because they are subsets).

Additionally, the vocabulary - the names of attributes and information elements that are transported as content - used in the general Concise SWID data defintion - and corresponding Consise SWID profiles - are mapped to a more concise Integer index (FIXME when DONE e.g. "Evidence" is mapped to 42). A corresponding mapping table is registered at the IANA (ref IANA reg).

In essence, Concise SWID defuse some of the amount of data transported by using CBOR, reducing the available vocabulary to application-specific content, and mapping human-readable labels for that content to more concise indices. Concise SWID also reduce the flexibility of original SWID in order to simplify construction and validation of data transported, while remaining easily translatable into XML SWID format.

# General Concise SWID data definition

~~~ CDDL

software-identity = {
  global-attr,
  * content: [ entity / evidence / link / software-meta / payload / any-element], ; review for interoperability
  ? corpus: bool,
  ? patch: bool,
  ? media: text,
  name: text,
  ? supplemental: bool,
  tagId: text,
  ? tag-version: integer,
  ? version: text,
  ? version-scheme: NMTOKEN,
}

NMTOKEN = text            ; .regexp to add some validation?
NMTOKENS = [* NMTOKEN]

any-attr = text
any-element = any

date-time = time
any-uri = text 

global-attr = (
  * (text => any-attr),
  ? lang: text,
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
  * (directory: directory // file: file // process: process // resource: resource)
)

file = {
  filesystem-item,
  ? size: integer,
  ? version: text,
  * (text => any-attr),
}

filesystem-item = (
  meta-type,
  ? key: bool,
  ? location: text,
  name: text,
  ? root: text
)

directory = {
  filesystem-item,
  path-elements: [* (directory / file)],
}

process = {
  global-attr,
  name: text,
  ? pid: integer,
}

resource = {
  global-attr,
  type: text,
}

entity = {
  global-attr,
  meta-elements: [* meta-element],
  name: text,
  ? regid: any-uri,
  role: NMTOKENS,
  ? thumbprint: text,
}

evidence = {
  global-attr,
  resource-collection,
  ? date: date-time,
  ? device-id: text,
}

link = {
  global-attr,
  ? artifact: text,
  href: any-uri,
  ? media: text,
  ? ownership: ("shared" / "private" / "abandon"),
  rel: NMTOKEN,
  ? type: text,
  ? use: ("optional" / "required" / "recommended"),
}

software-meta = {
  global-attr,
  ? activation-status: text,
  ? channel-type: text,
  ? colloquial-version: text,
  ? description: text,
  ? edition: text,
  ? entitlement-data-required: bool,
  ? entitlement-key: text,
  ? generator: text,
  ? persistent-id: text,
  ? product: text,
  ? product-family: text,
  ? revision: text,
  ? summary: text,
  ? unspsc-code: text,
  ? unspsc-version: text,
}

payload = {
  global-attr
  resource-collection,
}

~~~

#  IANA considerations

This document includes requests to IANA.

#  Security Considerations

TODO There are, validation, denial of service, counterfeit, etc.

#  Acknowledgements

#  Change Log

First version -00

# Contributors

--- back
