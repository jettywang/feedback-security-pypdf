# Security

We strive to provide a library with secure defaults.

## Configuration

### Global

*pypdf* currently employs a set of global configuration values, whose descriptions and defaults are
available at {py:class}`~pypdf._configuration.Configuration`. They internally rely on
{py:mod}`contextvars`.

```{testsetup}
pypdf_test_setup("user/security", {
    "example.pdf": "../resources/example.pdf",
})
```

```{testcode}
from pypdf import Configuration, PdfReader, apply_configuration, overwrite_configuration

# Limit the values to the current scope.
# The changed configuration value will be reset when exiting the context manager.
with apply_configuration(maximum_declared_stream_length=10_000):
    reader = PdfReader("example.pdf")
    for page in reader.pages:
        # Do something with the page.
        pass

# Overwrite the values globally.
overwrite_configuration(maximum_declared_stream_length=5_000)
reader = PdfReader("example.pdf")
for page in reader.pages:
    # Do something with the page.
    pass
```

### Reading

*pypdf* currently employs the following reading limits on *PdfReader* instances:

* `root_object_recovery_limit` limits the number of objects to read before stopping with Root object recovery in
  non-strict mode. It defaults to 10 000. Setting it to `None` will fully disable this limit.

If you want to employ custom limits for the *PdfWriter* as well, the currently preferred way
is to initialize it from the reader, id est something like
`PdfWriter(clone_from=PdfReader("file.pdf", root_object_recovery_limit=42))`.

For *PdfWriter* instances, the following limits are employed for incremental reading:

* `incremental_clone_object_count_limit` limits the number of objects to read during cloning. It defaults to
  500 000. Setting it to `None` will fully disable this limit.
* `incremental_clone_object_id_limit` limits the maximum object ID to read during cloning. It defaults to
  1 000 000. Setting it to `None` will fully disable this limit.

## Inspecting and removing actions

PDF documents can carry actions in several places: the catalog open action,
the additional-actions (`/AA`) dictionaries of the document, pages,
annotations and form fields, the `/A` entry of link annotations and the
document level JavaScript name tree. Some of these actions execute scripts,
launch programs or open external files. A download service that only wants to
keep in-document navigation and explicitly allowed web links can inspect and
remove them without ever executing anything.

{py:class}`~pypdf.actions.ActionScanner` resolves indirect references, walks
`/Next` chains (a single action dictionary or an array of them) and terminates
on cyclic chains. Every {py:class}`~pypdf.actions.ActionFinding` records the
action type, the decision reason and every location from which the action is
reachable.

The default {py:class}`~pypdf.actions.ActionPolicy` keeps `/GoTo` and
`/SetOCGState` navigation plus `/URI` actions using the `http` and `https`
schemes. Everything else, including `/JavaScript`, `/Launch`, `/GoToR`,
`/GoToE` and rendition actions, is rejected. The accepted URI schemes, hosts
and extra action types are configurable.

```{testsetup}
pypdf_test_setup("user/security-actions", {
    "example.pdf": "../resources/example.pdf",
})
```

```{testcode}
from pypdf import PdfWriter
from pypdf.actions import ActionPolicy

writer = PdfWriter(clone_from="example.pdf")

scanner = writer.scan_actions()
for finding in scanner.denied_findings():
    print(finding.action_type, finding.source_paths, finding.reason)

# Only allow links to one explicit host in addition to in-document navigation.
policy = ActionPolicy(allowed_uri_hosts={"example.test"})
verification = writer.sanitize_actions(policy)
assert verification.denied_findings() == []

writer.write("out-sanitized-actions.pdf")
```

Plain navigation that is not represented as an action is always preserved:
catalog destination arrays and annotation `/Dest` entries are left untouched.

## Reporting possible vulnerabilities

Please refer to our [security policy](https://github.com/py-pdf/pypdf/security/policy).

## Invalid reports

### Exceptions

Most exceptions raised by our code are considered bugs or robustness issues and can be reported publicly.
We consider it the task of the library user to catch exceptions which could cause their service to crash, although we try to
only raise a known set of exception types.

### Cryptographic functions

We receive reports about possibly insecure cryptography from time to time. This includes the following aspects:

* Using the ARC4 cipher
* Using the AES cipher in ECB mode
* Using MD5 for hashing

These are requirements of the PDF standard, which we need to achieve the greatest compatibility with.
Although some of them might be deprecated in PDF 2.0, the PDF 2.0 adoption rate is very low and legacy documents need to be supported.

### XML parsing

We use `xml.minidom` for parsing XMP information. Given recent Python versions built against recent Expat versions, the usual attacks
(exponential entity expansion and external entity expansion) should not be possible. We have corresponding tests in place to ensure
this for the platforms our tests run against.

For some details, see [the official documentation](https://docs.python.org/3/library/xml.html#xml-security) and the
[README for defusedxml](https://github.com/tiran/defusedxml/blob/main/README.md#python-xml-libraries).

Please note that automated scanners tend to still flag any direct imports of XML modules from the Python standard library as unsafe.
There have been discussions about this being outdated already, but they are still being flagged.
