---
layout: home

hero:
  name: redirect-proxy
  text: Fast HTTP redirect server
  tagline: Rules in a plain file, managed from a web administration, a REST API or the command line. One self-contained OTP release, for Docker, Debian and Homebrew.
  image:
    src: /logo.png
    alt: redirect-proxy, a star riding a router between two arrows
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: Redirection rules
      link: /guide/rules
    - theme: alt
      text: GitHub
      link: https://github.com/janalis/redirect-proxy

features:
  - icon: ⚡
    title: Fast and highly concurrent
    details: The compiled rule set lives in persistent_term, read by every request without locks. Exact rules are O(1) lookups, and prefix and regex rules are indexed.
    link: /guide/performance
    linkText: Performance
  - icon: 🛡️
    title: Hard to break
    details: An invalid rules file is never loaded, every write is atomic and backed up, regular expressions run with a backtracking budget, and OTP supervises it all.
    link: /guide/operations
    linkText: Operations
  - icon: 🧭
    title: Web administration
    details: Search, filter and edit rules, change many at once, test a URL and see which rule applies, preview imports, and read the audit log field by field.
    link: /guide/administration
    linkText: Administration
  - icon: 🔌
    title: REST API
    details: OAuth 2.0 client credentials from the built-in token endpoint, or JWTs from your own authorization server. An OpenAPI 3.1 document describes it.
    link: /guide/api
    linkText: REST API
  - icon: 🔐
    title: Sign-in your way
    details: Local accounts, OpenID Connect single sign-on or headers from a trusted reverse proxy, with viewer, editor and admin roles.
    link: /guide/authentication
    linkText: Authentication
  - icon: 📈
    title: Observable
    details: Prometheus metrics, health and readiness endpoints, hit counts per rule, and access logs in Combined, Common, JSON or your own format.
    link: /guide/monitoring
    linkText: Monitoring
---
