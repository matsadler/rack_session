# Rack Session

A Rust implementation of Ruby's `Rack::Session::Cookie` encoding, compatible
with Serde.

This crate only handles the encoding/decoding and message authentication,
you'll have to manage setting the cookies and attributes with whichever http
server or web framework you're using.

## Configuration

Given `Rack::Session::Cookie` setup in Ruby as such:

```ruby
use Rack::Session::Cookie,
  coder: Rack::Session::Cookie::Base64::JSON,
  secret: "super secret",
  old_secret: "not so secret"
```

The Rust equivalent with this crate would be:

```rust
use rack_session::{Cookie, Base64, Json};

fn main() {
  let mut coder = Cookie::<Base64<Json>>::new("super secret");
  coder.add_read_key("not so secret");

  /// hand coder off to code handling cookies
}
```

This crate does not provide the option of omitting the `secret` parameter like
the Ruby version does. It's not safe to use this style of client side session
without the message authentication enabled when the secret is provided.

The Ruby `Rack::Session::Cookie` implements a number of 'coder' classes for
serialising and deserialising the cookie value, the counterparts in this crate
are as follows:

| Ruby coder class                         | Rust type                     |
| ---------------------------------------- | ----------------------------- |
| `Rack::Session::Cookie::Base64::Marshal` | unimplemented                 |
| `Rack::Session::Cookie::Base64::JSON`    | `Cookie::<Base64<Json>>`      |
| `Rack::Session::Cookie::Base64::ZipJSON` | `Cookie::<Base64<Zip<Json>>>` |
| `Rack::Session::Cookie::Base64`*         | unimplemented                 |
| `Rack::Session::Cookie::Identity`*       | unimplemented                 |

\* impractical to actually use

Unfortunately there is not yet a Rust parser for Ruby's marshal format, so the
default `Base64::Marshal` coder class can not be implemented.

## Example

```rust
use serde::{Deserialize, Serialize};

use rack_session::{Base64, Cookie, Json};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Session {
    session_id: String,
    user_id: Option<u64>,
    is_signed_in: bool,
}

fn main() {
    let cookie = Cookie::<Base64<Json>>::new("super secret");

    let session = Session {
        session_id: String::from("ac762bf56f7360fc45701ff8373ed519c103762bf57bec09d5280659f59cb038"),
        user_id: Some(42),
        is_signed_in: true,
    };

    let encoded = cookie.to_string(&session).unwrap();

    let decoded = cookie.from_str::<Session>(&encoded).unwrap();

    assert_eq!(session, decoded);
}
```
