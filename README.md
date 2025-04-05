# jwt-token-

A JSON Web Token (JWT) vulnerability typically arises when developers incorrectly validate, decode, or trust JWTs. Here's a rundown of common **JWT vulnerabilities**, how they work, and some **lab ideas** if you're building a test environment.

---

Perfect, Harsh — let’s deep dive into more detailed JWT vulnerability scenarios, including **realistic setups**, **detection methods**, **manual & automated exploitation**, and **lab creation tips** for each. This will help you master both offensive and defensive aspects of JWTs.

---

##  Deep JWT Vulnerability Scenarios (Advanced)

---

### **1. `alg: none` Bypass (Signature Skipping)**
####  Detection:
- Decode the JWT and check the `alg` field.
- If the application does not validate the algorithm explicitly, it might fall back to accepting `"none"`.

####  Manual Exploitation:
1. Decode original token at [jwt.io](https://jwt.io).
2. Change header to:
   ```json
   { "alg": "none", "typ": "JWT" }
   ```
3. Keep payload same, remove signature (token ends with a dot).
4. Send to the target endpoint.

####  Flask Lab (Vulnerable):
```python
@app.route('/protected')
def protected():
    token = request.headers.get('Authorization').split()[1]
    data = jwt.decode(token, options={"verify_signature": False})
    if data['role'] == 'admin':
        return "Access granted"
    return "Access denied"
```

---

### **2. RS256 to HS256 Key Confusion (Algorithm Confusion Attack)**
####  Detection:
- JWT header has `"alg": "RS256"`.
- Public key is accessible (often via `.well-known/jwks.json` or source code).

####  Manual Exploitation:
1. Extract public key (PEM format).
2. Modify token:
   ```json
   { "alg": "HS256", "typ": "JWT" }
   ```
3. Sign token with **public key as HMAC secret**:
   ```bash
   jwt_tool original.jwt -X alg=HS256 -S public.pem
   ```
4. Use token and gain unauthorized access.

####  Node.js Lab:
```javascript
jwt.verify(token, pubKey); // doesn't check if alg is actually RS256
```

---

### **3. Weak HMAC Secret (Brute-Forceable)**
####  Detection:
- `alg` is HS256/HS512.
- Look for common JWT secrets (e.g., `JWT_SECRET`, `123456`, `admin`) in source code or `.env` files.

####  Manual Exploitation:
- Use tool:
  ```bash
  c-jwt-cracker token.jwt /usr/share/wordlists/rockyou.txt
  ```

####  Node.js Lab:
```javascript
const token = jwt.sign({ user: 'admin' }, 'secret123');
```

---

### **4. Expired Token Still Works (Improper `exp` Enforcement)**
####  Detection:
- Decode JWT and check `exp`.
- If `exp` is in the past but token still works, it’s a bug.

####  Exploitation:
- Reuse token indefinitely.
- Forge tokens with past `iat`/`exp`.

####  Lab:
```python
@app.route('/dashboard')
def dashboard():
    token = request.headers.get('Authorization').split()[1]
    data = jwt.decode(token, "secret123", algorithms=["HS256"])  # no exp check
    return f"Welcome {data['user']}"
```

---

### **5. Storing Sensitive Data in JWT Payload**
####  Detection:
- Decode token and look for:
  - `password`, `hash`, `email`, `is_admin`, etc.
- Common in internal APIs.

####  Exploitation:
- Expse data via MITM, XSS, token leak.
- Sometimes base64 decoded JWT contains secrets like:
  ```json
  {
    "username": "admin",
    "password": "plaintext"
  }
  ```

---

### **6. JWT Injection (Payload Injection to Forge Claims)**
####  Detection:
- Application builds JWT from user-supplied data.

####  Exploitation:
- Input a crafted payload like:
  ```json
  {
    "user": {"$ne": null}
  }
  ```
- In NoSQL systems like MongoDB, this may bypass logic:
  ```js
  db.find({user: payload.user})
  ```

---

### **7. JWT Replay Attack**
####  Detection:
- No short TTL (`exp`) on JWT.
- No logout token invalidation or token revocation list.

####  Exploitation:
- Intercept token via:
  - XSS
  - Logs
  - Misconfigured CORS
- Reuse token for persistent access.

---

### **8. Cross-Service Token Misuse**
####  Detection:
- Multiple apps share same signing key.
- Access token works across subdomains/microservices.

####  Exploitation:
- Use JWT from frontend to access admin microservice.

####  Lab Setup:
- One frontend app issues tokens
- Admin panel validates same JWT (same key)

---

### **9. Insecure `kid` Header Injection (Key ID Manipulation)**
####  Detection:
- JWT includes `kid` in header.
- App uses `kid` to fetch key without validation.

####  Exploitation:
1. Inject path traversal:
   ```json
   { "kid": "../../../../../../etc/passwd" }
   ```
2. Inject malicious `kid` to load controlled key.

####  Lab:
```js
const key = fs.readFileSync(`keys/${decoded.header.kid}.pem`);
```

---

### **10. Client-Side JWT Validation Only**
####  Detection:
- JavaScript validates JWT before sending requests.
- No server-side auth check.

####  Exploitation:
- Modify JWT in dev tools or localStorage.
- Replay request with altered role.

####  Exploitable Code:
```javascript
if (decodedToken.role === 'admin') {
  showAdminPanel();
}
```

---

## 🔬 Detection Workflow (Red Team / Bug Bounty)

1. **Use BurpSuite or ZAP to capture JWT**
2. Decode with:
   - [jwt.io](https://jwt.io)
   - `jwt_tool`, `jwt-cli`, or `CyberChef`
3. Analyze:
   - `alg`, `exp`, `nbf`, `iat`
   - Payload structure
   - Headers like `kid`, `jku`
4. Try tampering:
   - Change `alg`, `role`, `sub`, etc.
5. Observe server response for bypasses or crashes.

---

##  Lab Setup Suggestions

| Scenario | Stack | Difficulty |
|---------|-------|------------|
| `alg:none` | Flask or Express |  Easy |
| RS256 → HS256 | Node.js + RSA keys |  Medium |
| Brute-force | Flask + weak secret |  Easy |
| Expired reuse | Flask or Node |  Easy |
| Sensitive data in payload | Flask + dummy secrets |  Easy |
| Replay | Basic web app + static token |  Easy |
| `kid` injection | Node.js with dynamic key loading |  Hard |


---

## 🔧 Tools

-  [`jwt_tool`](https://github.com/ticarpi/jwt_tool)
-  [`jwt-cracker`](https://github.com/brendan-rius/c-jwt-cracker)
-  [`HackTricks JWT Cheatsheet`](https://book.hacktricks.xyz/pentesting-web/auth-bypass/json-web-tokens-jwt)

---

If you want, I can help you set up a vulnerable JWT lab using Flask, Node.js, or Docker. Just let me know what stack you prefer.
