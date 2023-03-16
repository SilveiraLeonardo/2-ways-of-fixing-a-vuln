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

@RestController
@EnableAutoConfiguration
@PropertySource("classpath:application.properties")
public class CommentsController {
  @Value("${app.secret}")
  private String secret;

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments", method = RequestMethod.GET, produces = "application/json")
  List<Comment> comments(@RequestHeader(value="x-auth-token") String token) {
    User.assertAuth(secret, token);
    // Validate user authorization to perform action
    User.assertAuthorization(token);
    return Comment.fetch_all();
  }

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments", method = RequestMethod.POST, produces = "application/json", consumes = "application/json")
  Comment createComment(@RequestHeader(value="x-auth-token") String token, @RequestBody CommentRequest input) {
    // Validate user access to requested object
    User.assertAuth(secret, token);
    // Validate user authorization to perform action
    User.assertAuthorization(token);
    // Validate input
    if (!validateInput(input)) {
      throw new BadRequest("Invalid input");
    }
    // Sanitize user input
    input.username = StringEscapeUtils.escapeHtml4(input.username);
    input.body = StringEscapeUtils.escapeHtml4(input.body);
    try {
      return Comment.create(input.username, input.body);
    } catch (Exception e) {
      throw new ServerError("Error creating comment");
    }
  }

  @CrossOrigin(origins = "*")
  @RequestMapping(value = "/comments/{id}", method = RequestMethod.DELETE, produces = "application/json")
  Boolean deleteComment(@RequestHeader(value="x-auth-token") String token, @PathVariable("id") String id) {
    // Validate user access to requested object
    User.assertAuth(secret, token);
    // Validate user authorization to perform action
    User.assertAuthorization(token);
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