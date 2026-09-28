# Maven

Skein is a Maven repository for your organization's own releases:
`mvn deploy` puts one here, and any build with the token resolves it
back. Nothing about your build changes except `settings.xml` and where
you deploy to.

Everything is private. Every request is a person with a token — there
is no anonymous read, and no artifact is visible to anybody outside your
organization.

## What works

- **`mvn deploy` of release versions** — the jar, the POM, sources and
  javadoc jars, any other classifier, and the `.sha1`/`.md5` Maven
  uploads beside each file.
- **Resolving** by exact version and by version range (`[1.0,2.0)`),
  from a `maven-metadata.xml` Skein generates from what it holds. The
  document's `<release>` and `<latest>` name the newest version that is
  not yanked; the deprecated `RELEASE`/`LATEST` keywords read them, but
  have not been run against Skein with the real client.
- **Licences** read from the POM's `<licenses>`, for the package page and
  the admission policy.
- **Yank** from the UI or the API: the version drops out of what a range
  resolves to and still downloads by its exact coordinate,
  so a build that pinned it keeps building.

Checked against the real `mvn` (3.9) on every change: the `clients` CI
job deploys a jar project twice, resolves it through a version range
into an empty local repository with `checksumPolicy=fail`, compiles
against it and runs it, and checks that each refusal below reaches the
person in Maven's own output.

## Configuring Maven

**Connect a client → Maven** in the UI fills this in for your registry
and mints the token. By hand, `~/.m2/settings.xml` — a repository in an
always-active profile, and a `<server>` with the same `id` carrying the
token:

```xml
<settings>
  <servers>
    <server>
      <id>skein</id>
      <username>skein</username>
      <password>skein_…</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>skein</id>
      <repositories>
        <repository>
          <id>skein</id>
          <url>https://skein.example.com/maven/</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles><activeProfile>skein</activeProfile></activeProfiles>
</settings>
```

- The **username is not checked**; the token in `<password>` is the
  credential. Maven sends it as HTTP Basic, and only after Skein has
  challenged it — which Skein does for every request without one.
- A token minted with `package:read` resolves; deploying needs
  `package:write`, and a person whose role is *reader* cannot deploy
  whatever their token says.
- A `<repository>` and **not** a `<mirror>` of `*`. Skein does not proxy
  Maven Central, so mirroring everything through it would fail every
  build on its first third-party dependency. With a repository, Maven
  asks Central and Skein, and each answers for what it has.
- `<snapshots>` is off because Skein holds none (see below); leaving it
  on only sends Maven to ask for snapshots that cannot be there.

### Skein must be HTTPS

Maven 3.8.1 and later refuse any plain-`http://` repository that is not
on the local machine — the `maven-default-http-blocker` mirror in
Maven's own global settings. Put TLS in front of Skein and set
`SKEIN_PUBLIC_URL` to the `https://` address (see
[operations](operations.md)). `http://localhost` and `http://127.0.0.1`
work for trying it out.

### A certificate from your own CA

If Skein's certificate comes from your company's own CA, Maven trusts what the JVM trusts. Add the CA to a copy of the
JDK's trust store and hand it to Maven:

```sh
cp "$JAVA_HOME/lib/security/cacerts" ~/.m2/truststore.jks
keytool -importcert -noprompt -alias acme-ca -file /etc/pki/acme-ca.pem \
  -keystore ~/.m2/truststore.jks -storepass changeit
export MAVEN_OPTS="-Djavax.net.ssl.trustStore=$HOME/.m2/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit"
```

## Deploying

Name the repository in the project's `distributionManagement` — a
deployment target is a property of the project, not of your settings:

```xml
<distributionManagement>
  <repository>
    <id>skein</id>
    <url>https://skein.example.com/maven/</url>
  </repository>
</distributionManagement>
```

or, without touching the POM:

```sh
mvn deploy -DaltDeploymentRepository=skein::https://skein.example.com/maven/
```

The `<id>` must match the `<server>` in `settings.xml`, or Maven has no
credential to send.

`mvn deploy` sends each file of a release as its own request, in an
order nothing promises. The first creates the version and the rest are
added to it; **a second upload of a filename that is already there is
refused** rather than overwriting it. So a re-run of a release job, or
`-Dmaven.deploy.overwrite`, cannot replace bytes somebody has already
built against — deploy a new version instead. A version's page names
the person and the token that deployed its first file.

`maven-metadata.xml` is generated from what Skein holds, and so is its
`.sha1` and `.sha256`, computed over the document in the same request.
The copy `mvn deploy` uploads is accepted and discarded: it was
assembled from what the deploying machine knew, not from what this
repository holds.

### Licences

The licence comes from the POM's `<licenses>` block, through a small
curated table of the spellings that actually appear
(`Apache License, Version 2.0`, `MIT`, `The BSD License`, the Eclipse,
GPL, LGPL and Mozilla licences, …). Several `<license>` entries are
joined with `AND`, because a Maven project under several licences is
under all of them. A name the table does not know — or a POM that
inherits its licence from a parent, or sets it through a property — is
**unknown** rather than a guess: turning "Apache License" into
`Apache-2.0` would admit an Apache 1.1 artifact under a rule written for
2.0.

The POM does not have to arrive first. The licence lands on the version
whichever file of it came first, and it is only ever filled in, never
replaced by a later POM.

## When Maven says no

Maven prints the status line of a refusal and never its body:

```
Could not transfer artifact com.acme:widget:pom:1.0.0 from/to skein (…):
status code: 409, reason phrase: widget-1.0.0.pom is already deployed at
com.acme:widget 1.0.0, and a published file never changes here (409)
```

so Skein writes its reason into the **reason phrase**, where Maven shows
it. (A reverse proxy that rewrites status lines leaves Maven with only
the standard phrase — `Conflict` — and then this table is what the
status means.)

| Status | Meaning |
|---|---|
| **401** | No token, or one that does not verify — revoked, expired, mistyped. Check that the `<server>` `id` matches the repository's. |
| **403** | Your role or your token does not reach this: a *reader* deploying, or a token minted without `package:write`. The reason says which. |
| **404** | Not here: no such artifact or version — or Maven is switched off for this registry, which answers every request the same way. |
| **409** | That file of that version is already deployed. Published files never change; deploy a new version. |
| **400** | A `-SNAPSHOT` version, or a path that is not `groupId/…/artifactId/version/file`. |
| **413** | One file over 128 MiB. |

## Limits

- **No SNAPSHOTs.** A snapshot is a version whose bytes are meant to
  change, and a published version's bytes never change here — the
  invariant the provenance and the licence gate rest on. A deploy of any
  `-SNAPSHOT` version is refused with a `400` that says so. If your
  release job publishes a snapshot on every merge, this is the thing to
  check before adopting Skein; publish release versions instead (a
  build number in the version works).
- **No proxy of Maven Central.** Skein serves what your organization
  deploys; Central still answers, from your machines, for everything
  else. Only npm has a pull-through proxy today.
- **One file: 128 MiB.** A package name (`groupId:artifactId`): 214
  bytes. A version: 128 bytes.
- **Paths are coordinates, strictly.** Every path segment is ASCII; a
  `..`, an empty segment or a control character is refused rather than
  cleaned up, because cleaning it up would let two different paths
  address one stored file. Names and versions are compared
  case-insensitively: `com.acme:Widget` and `com.acme:widget` are one
  artifact.
- **`maven-metadata.xml` checksums**: `.sha1` and `.sha256`. An `.md5` or
  `.sha512` of the metadata is absent rather than wrong, which Maven
  treats as a warning and carries on.
- **Gradle** publishes with the same protocol, but has not been checked
  against Skein with the real client; until it is, treat it as untested.
