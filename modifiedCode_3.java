package com.scalesec.vulnado;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.autoconfigure.*;
import java.util.List;
import java.io.Serializable;
import java.util.UUID;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;

@RestController
@EnableAutoConfiguration
public class CommentsController {
  @Value("${app.secret}")
  private String secret;

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments", method = RequestMethod.GET, produces = "application/json")
  List<Comment> comments(@RequestHeader(value="x-auth-token") String token) {
    if (!User.isAuthorized(token)) {
      throw new BadRequest("Unauthorized");
    }
    return Comment.fetch_all();
  }

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments", method = RequestMethod.POST, produces = "application/json", consumes = "application/json")
  Comment createComment(@RequestHeader(value="x-auth-token") String token, @RequestBody CommentRequest input) {
    if (!User.isAuthorized(token)) {
      throw new BadRequest("Unauthorized");
    }
    if (!input.username || !input.body) {
      throw new BadRequest("Missing required fields");
    }
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(input.body.getBytes("UTF-8"));
      String encodedHash = DatatypeConverter.printHexBinary(hash);
      SecretKey secretKey = new SecretKeySpec(secret.getBytes(), "AES");
      String encryptedBody = AES.encrypt(encodedHash, secretKey);
      String commentId = UUID.randomUUID().toString();
      return Comment.create(commentId, input.username, encryptedBody);
    } catch (Exception e) {
      throw new ServerError("Error encrypting comment body");
    }
  }

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments/{id}", method = RequestMethod.DELETE, produces = "application/json")
  Boolean deleteComment(@RequestHeader(value="x-auth-token") String token, @PathVariable("id") String id) {
    if (!User.isAuthorized(token)) {
      throw new BadRequest("Unauthorized");
    }
    return Comment.delete(id);
  }
}

class CommentRequest implements Serializable {
  public String username;
  public String body;
}

@ResponseStatus(HttpStatus.BAD_REQUEST)
class BadRequest extends RuntimeException {
  public BadRequest(String exception) {
    super(exception);
  }
}

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
class ServerError extends RuntimeException {
  public ServerError(String exception) {
    super(exception);
  }
}