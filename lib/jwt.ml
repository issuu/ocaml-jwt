(* ocaml-jwt
 * https://github.com/besport/ocaml-jwt
 *
 * Copyright (C) Be Sport
 * Author Danny Willems
 *
 * This program is released under the LGPL version 2.1 or later (see the text
 * below) with the additional exemption that compiling, linking, and/or using
 * OpenSSL is allowed.
 *
 * As a special exception to the GNU Library General Public License, you
 * may also link, statically or dynamically, a "work that uses the Library"
 * with a publicly distributed version of the Library to produce an
 * executable file containing portions of the Library, and distribute
 * that executable file under terms of your choice, without any of the
 * additional requirements listed in clause 6 of the GNU Library General
 * Public License.  By "a publicly distributed version of the Library",
 * we mean either the unmodified Library, or a
 * modified version of the Library that is distributed under the
 * conditions defined in clause 3 of the GNU Library General Public
 * License.  This exception does not however invalidate any other reasons
 * why the executable file might be covered by the GNU Library General
 * Public License.
*)

type failure = [`Bad_token | `Bad_payload]

(* ------------------------------- *)
(* ---------- Algorithm ---------- *)

(* IMPROVEME: add other algorithm *)
type algorithm =
  | RS256 of Nocrypto.Rsa.priv
  | HS256 of Cstruct.t
  | HS512 of Cstruct.t

let fn_of_algorithm = function
  | RS256 key -> (fun input_str -> Nocrypto.Rsa.PKCS1.sign ~hash:`SHA256 ~key (`Message (Cstruct.of_string input_str)) |> Cstruct.to_string)
  | HS256 key -> (fun input_str -> Nocrypto.Hash.SHA256.hmac ~key (Cstruct.of_string input_str) |> Cstruct.to_string)
  | HS512 key -> (fun input_str -> Nocrypto.Hash.SHA512.hmac ~key (Cstruct.of_string input_str) |> Cstruct.to_string)

let string_of_algorithm = function
  | RS256 _ -> "RS256"
  | HS256 _ -> "HS256"
  | HS512 _ -> "HS512"

let algorithm_of_string = function
  (* | "HS256" -> HS256 "" *)
  (* | "HS512" -> HS512 "" *)
  | _       -> Error `Bad_payload
(* ---------- Algorithm ---------- *)
(* ------------------------------- *)


(* ---------------------------- *)
(* ---------- Header ---------- *)

type header =
{
  alg : algorithm ;
  typ : string option; (* IMPROVEME: Need a sum type *)
}

let header_of_algorithm ?typ alg = { alg ; typ }

(* ------- *)
(* getters *)

let algorithm_of_header h = h.alg

let typ_of_header h = h.typ

(* getters *)
(* ------- *)

let json_of_header header =
  `Assoc
    (("alg", `String (string_of_algorithm (algorithm_of_header header))) ::
     (match typ_of_header header with
      | Some typ -> [("typ", `String typ)]
      | None -> []))

let string_of_header header =
  let json = json_of_header header in Yojson.Basic.to_string json

let header_of_json json =
  let alg = Yojson.Basic.Util.to_string (Yojson.Basic.Util.member "alg" json) in
  let typ = Yojson.Basic.Util.to_string_option (Yojson.Basic.Util.member "typ" json) in
  match algorithm_of_string alg with
  | Ok alg -> Ok { alg; typ }
  | e -> e

let header_of_string str =
  header_of_json (Yojson.Basic.from_string str)

(* ----------- Header ---------- *)
(* ----------------------------- *)

(* ---------------------------- *)
(* ----------- Claim ---------- *)

type claim         = string

let claim c        = c

let string_of_claim c = c

(* ------------- *)
(* Common claims *)

(* Issuer: identifies principal that issued the JWT *)
let iss            = "iss"

(* Subject: identifies the subject of the JWT *)
let sub            = "sub"

(* Audience: The "aud" (audience) claim identifies the recipients that the JWT
 * is intended for. Each principal intended to process the JWT MUST identify
 * itself with a value in the audience claim. If the principal processing the
 * claim does not identify itself with a value in the aud claim when this claim
 * is present, then the JWT MUST be rejected. *)
let aud            = "aud"

(* Expiration time: The "exp" (expiration time) claim identifies the expiration
 * time on or after which the JWT MUST NOT be accepted for processing. *)
let exp            = "exp"

(* Not before: Similarly, the not-before time claim identifies the time on which
 * the JWT will start to be accepted for processing. *)
let nbf            = "nbf"

(* Issued at: The "iat" (issued at) claim identifies the time at which the JWT
 * was issued.
 *)
let iat            = "iat"

(* JWT ID: case sensitive unique identifier of the token even among different
 * issuers.
 *)
let jti            = "jti"

(* Token type *)
let typ            = "typ"

(* Content type: This claim should always be JWT *)
let ctyp           = "ctyp"

(* Message authentication code algorithm (alg) - The issuer can freely set an
 * algorithm to verify the signature on the token. However, some asymmetrical
 * algorithms pose security concerns.
 *)
let alg            = "alg"

(* Common claims *)
(* ------------- *)

(* ------------------------- *)
(* Defined in OpenID Connect *)

(* Time when the End-User authentication occurred. Its value is a JSON number
 * representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC
 * until the date/time.
 *)
let auth_time      = "auth_time"

(* String value used to associate a Client session with an ID Token, and to
 * mitigate replay attacks. The value is passed through unmodified from the
 * Authentication Request to the ID Token. If present in the ID Token, Clients
 * MUST verify that the nonce Claim Value is equal to the value of the nonce
 * parameter sent in the Authentication Request. If present in the
 * Authentication Request, Authorization Servers MUST include a nonce Claim in
 * the ID Token with the Claim Value being the nonce value sent in the
 * Authentication Request. Authorization Servers SHOULD perform no other
 * processing on nonce values used. The nonce value is a case sensitive string.
 *)
let nonce          = "nonce"

let acr            = "acr"

let amr            = "amr"

let azp            = "azp"

(* Defined in OpenID Connect *)
(* ------------------------- *)

(* ----------- Claim ---------- *)
(* ---------------------------- *)

(* ------------------------------ *)
(* ----------- Payload ---------- *)

(* The payload a list of claim. The first component is the claim identifier and
 * the second is the value.
 *)
type payload = (claim * string) list

let empty_payload = []

let add_claim claim value payload =
  (claim, value) :: payload

let find_claim claim payload =
  let (_, value) =
    List.find (fun (c, _) -> (string_of_claim c) = (string_of_claim claim)) payload
  in
  value

let map f p = List.map f p

let rec all_ok = function
  | [] -> Ok []
  | (Error e)::_ -> Error e
  | (Ok x)::xs ->
      match all_ok xs with
      | Ok xs -> Ok (x::xs)
      | Error e -> Error e

let payload_of_json json =
  json
  |> Yojson.Basic.Util.to_assoc
  |> List.map
    (function
    | (claim, `String value) -> Ok (claim, value)
    | (claim, `Int value) -> Ok (claim, string_of_int value)
    | _ -> Error `Bad_payload)
  |> all_ok

let payload_of_string str =
  payload_of_json (Yojson.Basic.from_string str)

let json_of_payload payload =
  let members =
    map
      (fun (claim, value) -> ((string_of_claim claim), `String value))
      payload
  in
  `Assoc members

let string_of_payload payload =
  Yojson.Basic.to_string (json_of_payload payload)

(* ----------- Payload ---------- *)
(* ------------------------------ *)

(* -------------------------------- *)
(* ----------- JWT type ----------- *)

type t =
{
  header : header ;
  payload : payload ;
  signature : string
}

let b64_url_encode str =
  B64.encode ~pad:false ~alphabet:B64.uri_safe_alphabet str

let b64_url_decode str =
  B64.decode ~alphabet:B64.uri_safe_alphabet str

let of_header_and_payload header payload =
  let b64_header = (b64_url_encode (string_of_header header)) in
  let b64_payload = (b64_url_encode (string_of_payload payload)) in
  let algo = fn_of_algorithm (algorithm_of_header header) in
  let unsigned_token = b64_header ^ "." ^ b64_payload in
  let signature = algo unsigned_token in
  { header ; payload ; signature }
(* ------- *)
(* getters *)

let header t = t.header

let payload t = t.payload

let signature t = t.signature

(* getters *)
(* ------- *)

let to_token t =
  let b64_header = (b64_url_encode (string_of_header (header t))) in
  let b64_payload = (b64_url_encode (string_of_payload (payload t))) in
  let b64_signature = (b64_url_encode (signature t)) in
  b64_header ^ "." ^ b64_payload ^ "." ^ b64_signature

let of_token token =
  try
    let token_splitted = Re.Str.split_delim (Re.Str.regexp_string ".") token in
    match token_splitted with
    | [ header_encoded ; payload_encoded ; signature_encoded ] ->
        (match header_of_string (b64_url_decode header_encoded) with
          | Error e -> Error e
          | Ok header ->
            (match payload_of_string (b64_url_decode payload_encoded) with
            | Ok payload ->
              let signature = b64_url_decode signature_encoded in
              Ok { header ; payload ; signature }
            | Error e -> Error e))
    | _ -> Error `Bad_token
  with _ -> Error `Bad_token

(* ----------- JWT type ----------- *)
(* -------------------------------- *)
