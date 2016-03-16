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

--- abstract 

This document defines a concise representation of ISO 19770-2:2015 Software Identifiers (SWID tags) that is interoperable with the XML schema definition of ISO 19770-2:2015. Additionally, this document defines application specific profiles -- small subsets of SWID content that are derived from SWID tag vocabulary -- to enable better scalability when transporting SWID tag related information in constraint environments.

--- middle

# Introduction

SWID tags have several applications; including but not limited to:

* Software Inventory Management, a part of the Software Asset Management (SAM) process {{SAM}}, which requires an accurate list of discernible deployed software instances.

* Vulnerability Assessment, which requires a semantic link between standardized vulnerability descriptions and IT-assets.

* Remote Attestation, which benefits from an accompanying list of golden (well-known) measurements about software.

Software Identifier tags are meant to be flexible and able to express virtually any type of software and their associated metadata - even the software's installation packages on installation media. Therefore, the complete set of attributes or types of information elements that can be included in a Software Identifier tag often exceeds the scope a single application of SWID. Unfortunately, this flexibility also limits the capabilities of validation and can require a significant amount of resources to cope with its consequences.

As a basis, this documents provides a more concise representation of SWID tags in the CBOR {{-cbor}} described via the CDDL {{-cddl}} - the general Concise SWID data definition - that is interoperable with the XML schema definition of ISO-19770-2:2015 {{SWID}}. The vocabulary - i.e. the names of the attributes - used in the general Concise SWID data definition can be mapped to more concise Integer indices. This mapping is based on the well known attribute names and information element names defined in ISO-19770-2:2015.

Derived from this basis, the document defines Concise SWID profiles, which are subsets of the general Concise SWID data definition structure that represent (in a standardized way) only information elements that are required in specific applications. The content of a Concise SWID profile definition can be mapped to the XML schema definition of ISO-19770-2:2015 and uses the same vocabulary but they do not compose SWID tags and sometimes specify content that is not strictly defined in the XML schema definition of SWID tags.

In essence, Concise SWID defuse some of the amount of data transported by using CBOR and mapping human-readable labels for that content to more concise Integer labels (indices). Concise SWID profiles provide application specific subsets of SWID tags that sacrifice some flexibility of the original SWID tags to improve scalability in constraint environments via simpler construction and validation of data transported, while remaining translatable into XML SWID format by using the same vocabulary.

# General Concise SWID data definition (original vocabulary)

This is a complete representation of the content of the ISO-19770-2:2015 {{SWID}} XML schema definition in CDDL. It is possible to use this definition as a Concise SWID profile that is fully interoperable with the ISO-19770-2:2015 XSD -- but it carries the same baggage. The CamelCase notation used in the XML schema definition is changed to hyphen-separated notation (e.g. ResourceCollection is named resource-collection in the Concise SWID data definition). While the vocabulary is the same, a different notation was chosen to better destinguish the representations via the names of attributes and information elements written in English text.

~~~ CDDL

software-identity = {
  global-attr,
  * content: [ entity / evidence / link / software-meta / payload / any-element], ; review for interoperability
  ? corpus: bool,
  ? patch: bool,
  ? media: text,
  name: text,
  ? supplemental: bool,
  tag-id: text,
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
  ? reg-id: any-uri,
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

# General Concise SWID data definition (Integer labels)

This variant of the Concise SWID data definition uses Integers as labels for the members and information elements used in the maps. The CDDL remains human readable and the "mapping" of information element content to the actual Integer labels can be found at the bottom of the definition. 48 character strings of the SWID vocabulary that would have to be stored or transported in full if using the original vocabulary are replaced.

~~~ CDDL

software-identity = {
  global-attr,
  * content,
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
  global-attr
  resource-collection,
}

tag-id = (0: text)
name = (1: text)
content = (2: [ entity / evidence / link / software-meta / payload / any-element])
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

# Concise SWID profiles and profile applications

This section highlights three applications of Concise SWID profiles. Concise SWID profiles are very specialized subsets of SWID tag content, potentially including content that cannot normally be validated (if, for example, stored in an Any attribute or any-attr, respectively). A Concise SWID profile is basically stripped of everything that is not required by the application it is constructed for. Therefore, a Concice SWID profile does not compose a valid SWID tag, but it uses the same vocabulary in the CBOR data definition and can be translated into valid (Concise) SWID tags if the required information can be added.

In order to reduce size, some Concise SWID profiles use arrays instead of maps. Content is therefore not always identified via labels but also via sequence and type of array members. Every type of Concise SWID profile is associated with a unique profile-id (an Integer) to simplify parsing and validation.

## Profile Application: Software Inventory

A basic application of SWID tags is to make a software inventory available for other consumer of information. Typically, the complete set of SWID tags does not have to be transported to achieve this. In most cases, it is sufficient to transport a list composed of SWID tag-ids. If a corresponding complete SWID tag is stored in a back-end repository, the detail-rich content can be associated via the tag-id, if required.

### Software Inventory Profile

An empty array indicates that no SWID tags are available. If available, the device-id SHOULD contain an identifier the endpoint, on which the set of software is installed on, can be uniquely identified with (in a given scope or domain, e.g. an administrative domain).

~~~ CDDL

software-inventory = [
  profile-id,
  ? device-id,
  [ * tag-id ],
]

profile-id = 0
device-id = text
tag-id = text

~~~

## Profile Application: Vulnerability Assessment

A vital basis for a vulnerability assessment is the association of Common Vulnerabilities and Exposures identifiers {{CVE}} with specific instances of software installed on an endpoint. Software that can be identified via a SWID tag ("tag-id") can show multiple vulnerabilities ("cve-id"). If a member array of the vulnerability assessment profile only contains a SWID tag and no CVE identifiers, no vulnerabilities could be associated with that software instance. A standard-conform SWID tag can contain multiple instances of entity, evidence, link, (software-)meta, payload, or the any-element. In contrast, in support of the application of vulnerability assessment, the corresponding profile contains one or more CVE identifiers instead, represented by two integers - the CVE Year Portion and the CVE Sequence Number, from which a unique CVE identifier can be derived.

### Vulnerability Assessment Profile

~~~ CDDL

vulnerability-assessment = [
  profile-id,
  ? device-id,
  * [tag-id, * cve-id]
]

device-id = text
tag-id = text
cve-id = [year, sequence]
year = integer
sequence = integer
profile-id = 1

~~~

## Profile Application: Remote Attestation

Remote attestation describes the attempt to determine the integrity and trustworthiness of a computing platform or device without direct access. One way to do so is based on measurements of software components, where the hash values of all started software components are stored in (or extended into) a Trust Anchor implemented as a Hardware Security Module (such as TPM and similar) and reported via a signature over these measurements. In order to assess the trustworthiness of the target device, an attestation verifier needs to know the reference hashes (often referred to as golden measurements) to test the actual measurements against. The aggregated measurements typically come with a corresponding measurement log that includes the paths, names and hashes of the files that are part of the measurement. One way to transport these reference hashes to compare them with measurement logs is the use of specific SWID tag content that includes the reference hashes and -- ideally -- would be signed by the original manufacturer of the software.

### Reference Hash Profile

In general, SWID tag payload content can list files that may be installed with a software product. The subset of the payload structure used by this Concise SWID profile only includes the attributes that are required to represent a hierarchical file-system structure (i.e. directory and file, including the path-elements root, location and name, by which multiple files can be expressed in the form of a tree). Via this hierarchical structure the files that are included in the measurement log and their corresponding hash values are expressed. Although this could also be done via the evidence content, the payload structure contains the hash values of the files that are supplied by the manufacturer, in contrast to the evidence structure that would include hashes that are created by software running on the endpoint itself. In essence, the set of files and corresponding hashes transported in a Reference Hash profile can be used to compare them with a measurement log.

In a standard SWID tag, the hash value is stored in an Any attribute. In the Reference Hash profile, a file map references a set of hash-types and corresponding hash-values via a map member (e.g. "SHA256" : hash-value). 

~~~ CDDL

reference-hashes = [
  profile-id,
  directory,
]

filesystem-item = (root, location, name)

file = {
  filesystem-item,
  + (hash-type => hash-value),
}

hash-type = text
hash-value = text

directory = {
  filesystem-item,
  path-elements,
}

name = (1: text)
location = (17: text)
root = (18: text)
path-elements = (19: ([* (directory / file)]))
profile-id = 2

~~~

# COSE signatures for Concise SWID tags and Concise SWID profiles

Concise SWID tags require a different signature scheme than the ISO SWID tags represented via the XML schema definition. COSE provides the required mechanism, which will result in additional attributes to be included in the general Concise SWID data definition, e.g. signature-type ("compat", "cose", etc.).

#  IANA considerations

This document will include requests to IANA: Integer indices for SWID content attributes and information elements, and Concise SWID profile IDs.

#  Security Considerations

TODO There are, validation, denial of service, counterfeit, etc.

#  Acknowledgements

#  Change Log

First version -00

# Contributors

--- back
