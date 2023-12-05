+++
title = "FAQ"
description = "Answers to frequently asked questions."
date = 2021-05-01T19:30:00+00:00
updated = 2021-05-01T19:30:00+00:00
draft = false
weight = 30
sort_by = "weight"
template = "docs/page.html"

[extra]
toc = true
top = false
+++

<details>
<summary>How can I automatically reload code?</summary>
Try [cargo watch](https://crates.io/crates/cargo-watch):

```
$ cargo-watch -x check  -s 'cargo loco start'
```
</details>

<details>
<summary>Do I have to have `cargo` to run tasks or other things?</summary>
You don't have to run things through `cargo` but in development it's highly recommended. If you build `--release`, your binary contains everything including your code and `cargo` or Rust is not needed.
</details>

<br/>

<details>
<summary>Is this production ready?</summary>

Loco is still in its beginning, but its roots are not. It's almost a rewrite of `Hyperstackjs.io`, and Hyperstack is based on an internal Rails-like framework which is production ready.

Most of Loco is glue code around Axum, SeaORM, and other stable frameworks, so you can consider that.

At this stage, at version 0.1.x, we would recommend to _adopt and report issues_ if they arise.

</details>

<br/>
<details>
<summary>How can I add custom middleware?</summary>
TBD
</details>

<br/>

<details>
<summary>Can I inject custom state/configuration</summary>
TBD
</details>

<br/>

<details>
<summary>How can I disable application logger</summary>
TBD
</details>
