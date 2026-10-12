const SECRET_KEY = process.env.REACT_APP_SECRET_KEY;
export function sign(payload) { return hmac(SECRET_KEY, payload); }
