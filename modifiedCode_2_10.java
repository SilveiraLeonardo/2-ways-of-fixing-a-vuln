package com.scalesec.vulnado;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.autoconfigure.*;
import java.util.List;
import java.io.Serializable;
import java.util.UUID;
import java.security.SecureRandom;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

@RestController
@EnableAutoConfiguration
public class CommentsController {
  @Value("${app.secret}")
  private String secret;

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments", method = RequestMethod.GET, produces = "application/json")
  List<Comment> comments(@RequestHeader(value="x-auth-token") String token) {
    User.assertAuth(secret, token);
    return Comment.fetch_all();
  }

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments", method = RequestMethod.POST, produces = "application/json", consumes = "application/json")
  Comment createComment(@RequestHeader(value="x-auth-token") String token, @RequestBody CommentRequest input) {
    // Validate input
    if (input.username == null || input.body == null) {
      throw new BadRequest("Username and body are required fields");
    }
    if (!input.username.matches("^[a-zA-Z0-9_]{3,20}$")) {
      throw new BadRequest("Username must be between 3 and 20 characters and can only contain letters, numbers, and underscores");
    }
    if (input.body.length() > 140) {
      throw new BadRequest("Comment body must be 140 characters or less");
    }
    if (!input.token.matches("^[a-zA-Z0-9]{32}$")) {
      throw new BadRequest("Token must be 32 characters and can only contain letters and numbers");
    }
    if (!input.authToken.matches("^[a-zA-Z0-9]{32}$")) {
      throw new BadRequest("Auth token must be 32 characters and can only contain letters and numbers");
    }
    if (!input.authHash.matches("^[a-zA-Z0-9]{64}$")) {
      throw new BadRequest("Auth hash must be 64 characters and can only contain letters and numbers");
    }
    if (!input.authSecret.matches("^[a-zA-Z0-9]{32}$")) {
      throw new BadRequest("Auth secret must be 32 characters and can only contain letters and numbers");
    }
    if (!input.authNonce.matches("^[a-zA-Z0-9]{32}$")) {
      throw new BadRequest("Auth nonce must be 32 characters and can only contain letters and numbers");
    }
    if (!input.authSignature.matches("^[a-zA-Z0-9]{64}$")) {
      throw new BadRequest("Auth signature must be 64 characters and can only contain letters and numbers");
    }
    SecureRandom random = new SecureRandom();
    byte[] authToken = new byte[32];
    random.nextBytes(authToken);
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(authToken);
    SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(), "AES");
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] encryptedToken = cipher.doFinal(authToken);
    User.assertAuth(secret, token, encryptedToken);
    return Comment.create(input.username, input.body, encryptedToken, input.token, input.authToken, input.authHash, input.authSecret, input.authNonce, input.authSignature, input.userId, input.userId, input.userId, input.userId, input.commentOwnerId);
  }

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments/{id}", method = RequestMethod.DELETE, produces = "application/json")
  Boolean deleteComment(@RequestHeader(value="x-auth-token") String token, @PathVariable("id") String id, @RequestHeader(value="x-comment-token") String commentToken, @RequestHeader(value="x-auth-token") String authToken, @RequestHeader(value="x-auth-hash") String authHash, @RequestHeader(value="x-auth-secret") String authSecret, @RequestHeader(value="x-auth-nonce") String authNonce, @RequestHeader(value="x-auth-signature") String authSignature, @RequestHeader(value="x-user-id") String userId, @RequestHeader(value="x-comment-owner-id") String commentOwnerId) {
    User.assertAuth(secret, token, authToken, authHash, authSecret, authNonce, authSignature, userId);
    if (userId.equals(commentOwnerId)) {
      return Comment.delete(id, commentToken, userId, userId, userId, userId, commentOwnerId);
    } else {
      throw new Unauthorized("User is not authorized to delete this comment");
    }
  }
}

class CommentRequest implements Serializable {
  public String username;
  public String body;
  public String token;
  public String authToken;
  public String authHash;
  public String authSecret;
  public String authNonce;
  public String authSignature;
  public String userId;
  public String commentOwnerId;
}

@ResponseStatus(HttpStatus.BAD_REQUEST)
class BadRequest extends RuntimeException {
  public BadRequest(String exception) {
    super(exception);
  }
}

@ResponseStatus(HttpStatus.UNAUTHORIZED)
class Unauthorized extends RuntimeException {
  public Unauthorized(String exception) {
    super(exception);
  }
}

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
class ServerError extends RuntimeException {
  public ServerError(String exception) {
    super(exception);
  }
}