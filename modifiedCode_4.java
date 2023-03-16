package com.scalesec.vulnado;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.autoconfigure.*;
import java.util.List;
import java.io.Serializable;
import java.util.regex.Pattern;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpHeaders;
import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.security.spec.KeySpec;

@RestController
@EnableAutoConfiguration
@PropertySource("classpath:application.properties")
public class CommentsController {
  @Value("${app.secret}")
  private String secret;

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments", method = RequestMethod.GET, produces = "application/json")
  List<Comment> comments(@RequestHeader(value="x-auth-token") String token, HttpHeaders headers) {
    // Set secure headers
    headers.add("X-XSS-Protection", "1; mode=block");
    headers.add("X-Content-Type-Options", "nosniff");
    headers.add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    headers.add("X-Frame-Options", "DENY");
    headers.add("Content-Security-Policy", "default-src 'self'");
    headers.add("Referrer-Policy", "no-referrer");
    headers.add("X-XSS-Protection", "1; mode=block");
    // Validate user authentication
    if (!User.validateAuth(secret, token)) {
      throw new ServerError("Error validating user authentication");
    }
    // Validate user authorization to perform action
    if (!User.validateAuthorization(token)) {
      throw new ServerError("Error validating user authorization");
    }
    return Comment.fetch_all();
  }

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments", method = RequestMethod.POST, produces = "application/json", consumes = "application/json")
  Comment createComment(@RequestHeader(value="x-auth-token") String token, @RequestBody CommentRequest input, HttpHeaders headers) {
    // Set secure headers
    headers.add("X-XSS-Protection", "1; mode=block");
    headers.add("X-Content-Type-Options", "nosniff");
    headers.add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    headers.add("X-Frame-Options", "DENY");
    headers.add("Content-Security-Policy", "default-src 'self'");
    headers.add("Referrer-Policy", "no-referrer");
    headers.add("X-XSS-Protection", "1; mode=block");
    // Validate user authentication
    if (!User.validateAuth(secret, token)) {
      throw new ServerError("Error validating user authentication");
    }
    // Validate user authorization to perform action
    if (!User.validateAuthorization(token)) {
      throw new ServerError("Error validating user authorization");
    }
    // Validate user authorization to create comment
    if (!User.validateAuthorizationToCreate(token)) {
      throw new ServerError("Error validating user authorization to create comment");
    }
    // Validate input
    if (!validateInput(input)) {
      throw new BadRequest("Invalid input");
    }
    // Sanitize user input
    input.username = StringEscapeUtils.escapeHtml4(input.username);
    input.body = StringEscapeUtils.escapeHtml4(input.body);
    try {
      // Generate a secure secret key
      SecureRandom random = SecureRandom.getInstanceStrong();
      byte[] salt = new byte[16];
      random.nextBytes(salt);
      KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, 65536, 256);
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      byte[] hash = skf.generateSecret(spec).getEncoded();
      String secureSecret = Base64.getEncoder().encodeToString(hash);
      return Comment.create(input.username, input.body, secureSecret);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new ServerError("Error creating comment");
    }
  }

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments/{id}", method = RequestMethod.DELETE, produces = "application/json")
  Boolean deleteComment(@RequestHeader(value="x-auth-token") String token, @PathVariable("id") String id, HttpHeaders headers) {
    // Set secure headers
    headers.add("X-XSS-Protection", "1; mode=block");
    headers.add("X-Content-Type-Options", "nosniff");
    headers.add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    headers.add("X-Frame-Options", "DENY");
    headers.add("Content-Security-Policy", "default-src 'self'");
    headers.add("Referrer-Policy", "no-referrer");
    headers.add("X-XSS-Protection", "1; mode=block");
    // Validate user authentication
    if (!User.validateAuth(secret, token)) {
      throw new ServerError("Error validating user authentication");
    }
    // Validate user authorization to perform action
    if (!User.validateAuthorization(token)) {
      throw new ServerError("Error validating user authorization");
    }
    // Validate user authorization to delete comment
    if (!User.validateAuthorizationToDelete(token, id)) {
      throw new ServerError("Error validating user authorization to delete comment");
    }
    try {
      return Comment.delete(id);
    } catch (Exception e) {
      throw new ServerError("Error deleting comment");
    }
  }

  private boolean validateInput(CommentRequest input) {
    // Validate username
    if (!Pattern.matches("[a-zA-Z0-9_]+", input.username)) {
      return false;
    }
    // Validate body
    if (!Pattern.matches("[a-zA-Z0-9_\\s]+", input.body)) {
      return false;
    }
    // Validate for malicious code injection
    if (input.username.contains("<") || input.body.contains("<") || input.username.contains("<script>") || input.body.contains("<script>") || input.username.contains("<script") || input.body.contains("<script") || input.username.contains("&") || input.body.contains("&") || input.username.contains(";") || input.body.contains(";")) {
      return false;
    }
    return true;
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