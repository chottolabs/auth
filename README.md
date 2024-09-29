# side tangents

- https://jvns.ca/blog/2022/03/23/a-toy-version-of-tls/
- https://tls13.xargs.org/#client-hello
- https://zostay.com/posts/2022/05/04/do-not-use-libsodium-with-go/
- https://www.privateinternetaccess.com/blog/libsodium-v1-0-12-and-v1-0-13-security-assessment/

---

# simple-oauth

minimal example for google oauth 2.0

- implements PKCE
- implements JWT (defaults to HS256, ensure `32 * 8 = 256`)

```sh
GOOGLE_REDIRECT_URI=http://localhost:4321/auth/google/callback
GOOGLE_CLIENT_ID=***.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-***
```

```sh
JWT_SECRET=$(openssl rand -base64 32) go run main.go
```

related:
- https://jwt.io
- https://developers.google.com/identity/protocols/oauth2
- https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/
