package in.neuw.aws.openid.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

import java.util.List;

/**
 * @author Karanbir Singh on 06/01/2020
 */
@Getter
@Setter
@Accessors(chain = true)
@ToString
@JsonPropertyOrder({ "preferred_username", "roles" })
public class SecuredUserDetails {

    @JsonProperty("preferred_username")
    private String username;

    @JsonProperty("aws_roles")
    private List<String> arnRoles;

    @JsonProperty("roles")
    private List<String> awsRoleNames;

}
