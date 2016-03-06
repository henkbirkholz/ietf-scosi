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

SWID tags have several applications; including but not limited to: 
* Software Inventory Management, a part of the Software Asset Management (SAM) process (TODO REF ISO-19770-5:2013), which requires an accurate list of discernible deployed software instances.
* Vulnerability Assessment, which requires a semantic link between standardized vulnerability descriptions and IT-assets.
* Remote Attestation, which benefits from an accompanying list of golden (well-known) measurements about software.

Software Identifier tags are meant to be flexible and able to express virtually any type of software and their associated metadata. Therefore, the complete set of attributes or types of information elements that can be included in a Software Identifier tag often exceeds the scope a single application of SWID. Unfortunately, this flexibility also limits the capabilities of validation and can require a significant amount of resources to cope with its consequences.

As a basis, this documents provides a more concise representation of SWID tags in the CBOR {{-cbor}} described via the CDDL {{-cddl}} - the general Concise SWID data definition - that is interoperable with the XML schema definition of ISO-19770-2:2015 (FIXME someone pls have mercy on this sentence and rephrase it). Derived from this basis, the document defines Concise SWID profiles, which are subsets of the general Concise SWID data definition structure that represent (in a standardized way) only information elements that are required in specific applications. The Concise SWID profile defintions can be completely mapped to the XML schema definition of ISO-19770-2:2015 but not vice versa (because they are subsets) and do not include anthing equivalent to the XML any attribute.

Additionally, the vocabulary - the names of attributes and information elements that are transported as content - used in the general Concise SWID data defintion - and corresponding Consise SWID profiles - are mapped to a more concise Integer index (FIXME when DONE e.g. "Evidence" is mapped to 42). A corresponding mapping table is registered at the IANA (TODO ref IANA reg).

In essence, Concise SWID defuse some of the amount of data transported by using CBOR, reducing the available vocabulary to application-specific content, and mapping human-readable labels for that content to more concise indices. Concise SWID also reduce the flexibility of original SWID in order to simplify construction and validation of data transported, while remaining easily translatable into XML SWID format.

# General Concise SWID data definition

This is a complete representation of the content of the ISO-19770-2:2015 XML schema definition in CDDL. It is possible to use this definition as a Concise SWID profile that is fully interoperable with the ISO-19770-2:2015 XSD - but it carries the same baggage.

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
any-uri = uri 

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

# Concise SWID profile applications

This section highlights (FIXME a number) of profile applications Consice SWID profiles are defined for. A profile can apply to more than one profile application and a profile application can result in more than one profile.

## Software Inventory

The most basic application of Consise SWID tags is a list of every discernable software instance installed on an endpoint. This application does require...

## Vulnerability Assessment

which attributes and complex types are really essential for vulnerability assessment? This list is so long!

* YES: When producing SWID tags, tag creators MUST produce SWID tags that conform to all requirements defined in the ISO/IEC 19770-2:2015 specification.
* NO: The <SoftwareIdentity> element MUST specify an @xml:lang attribute with a non-blank value to indicate the default human language used for expressing all language-dependent attribute values. (TODO CHECK UTF-8 should take care of the problem?)
* IDK: Every <Entity> element MUST provide an explicit (i.e., non-default) @regid attribute value. (TODO CHECK, would we need this?)
* IDK: The <Entity> element containing the @role “tagCreator” MUST provide an explicit (i.e., non-default) @regid attribute value. (TODO CHECK, would we need this?)
* IDK: okay... I'll stop now. This is US3 from the NISTIR 8060 requirements v5 spread sheet.

What is really essential to vulnerabulity assessment here? This includes tpyical optional attributes. Or is there a problem to definde a subset. Maybe we have to parse every CVE and look for attributes it needs to be associated by?

## Remote Attestation

insert text here

# Mapping of lables and element names

In order to reduce the general size of a Concise SWID tag, this document defines a Concise SWID Mapping Table that translates lables and member names used in the general Concise SWID data definition to a corresponding integer value. The type tagID in Figure FIXME, for instance, replaces the member composed of lable and type in the map. This procedure moves the type visible definitions more down in the CDD (see Figure FIXME). The encoding can be detected implicitly, as the general Concise SWID data definition uses only strings as labes and member names and the reduced mapping only uses integers (FIXME this probably requires rephrasing?). Therefore, encpdings can be mixed without further indication.

~~~ CDDL

software-identity = {tagID}

tagID = (0: text)

~~~

~~~ CDDL

software-identity = {
  global-attr,
  * content,
  ? corpus,
  ? patch,
  ? media,
  name,
  ? supplemental,
  tagId,
  ? tag-version,
  ? version,
  ? version-scheme,
}

tagID = (0: text)
name = (1: text)
content = (2: [ entity / evidence / link / software-meta / payload / any-element])
corpus = (3: bool)
patch = (4: bool)
media = (5: text)
supplemental = (6: bool)
tag-version = (7: integer)
version = (8: text)
version-scheme (9: NMTOKEN)

~~~

# Concise SWID profiles

There is a minimal set of information elements that MUST be included in every Concise SWID profile in order to compose a valid SWID tag: name, and tagID. The only exception is the Concise Inventory Item, which only consists of a tagID and therefore cannot be translated into a valid ISO 19770-2/2015 XML SWID tag.

## Concise Inventory Item (FIXME cbor tag here)

The most minimal Concise SWID profile

~~~ CDDL

software-identityi = {tagId: text}

~~~

## Minimal Inventory Item (FIXME cbor tag here)

The most minimal SWID tag. 

~~~ CDDL

software-identityi = {
  tagId: text
}

~~~

## Inventory Item with version (FIXME cbor tag here)

## Inventory Item with version and depencies to other Inventory Items (FIXME cbor tag here)

TODO is this already enough for vulnerability assessement? See above

# COSE signatures for Concise SWID tags

# Canonical construction of XML SWID tags from Consice SWID tags

#  IANA considerations

This document includes requests to IANA.

#  Security Considerations

TODO There are, validation, denial of service, counterfeit, etc.

#  Acknowledgements

#  Change Log

First version -00

# Contributors

--- back
