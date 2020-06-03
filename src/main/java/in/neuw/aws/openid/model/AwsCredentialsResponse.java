package in.neuw.aws.openid.model;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.time.Instant;

/**
 * @author Karanbir Singh on 06/02/2020
 */
@Getter
@Setter
@Accessors(chain = true)
public class AwsCredentialsResponse {

    private String accessKeyId;
    private String secretAccessKey;
    //private String sessionToken;
    private Instant expiration;

}
