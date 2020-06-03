package in.neuw.aws.openid.service;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.keycloak.KeycloakSecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.GetRoleRequest;
import software.amazon.awssdk.services.iam.model.GetRoleResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

/**
 * @author Karanbir Singh on 06/01/2020
 */
@Slf4j
@Service
public class AwsCredManager {

    @Autowired
    private StsClient stsClient;

    @Autowired
    private IamClient iamClient;

    @Value("${AWS_SIGN_IN_URL}")
    private String SIGN_IN_URL;

    @Value("${keycloak.auth-server-url}")
    private String ISSUER_URL;

    @Value("${AWS_CONSOLE_URL}")
    private String CONSOLE_URL;

    @Value("${AWS_DEFAULT_STS_DURATION}")
    private Integer AWS_DEFAULT_STS_DURATION;

    @SneakyThrows
    public String getSignInUrl(final KeycloakSecurityContext securityContext, final String roleArn) {
        Credentials credentials = getCredentials(securityContext, roleArn);
        String sessionJson = String.format(
                "{\"%1$s\":\"%2$s\",\"%3$s\":\"%4$s\",\"%5$s\":\"%6$s\"}",
                "sessionId", credentials.accessKeyId(),
                "sessionKey", credentials.secretAccessKey(),
                "sessionToken", credentials.sessionToken());
        String getSigninTokenURL = SIGN_IN_URL +
                "?Action=getSigninToken" +
                "&DurationSeconds=43200" +
                "&SessionType=json&Session=" +
                URLEncoder.encode(sessionJson,"UTF-8");
        System.out.println(getSigninTokenURL);

        URL url = new URL(getSigninTokenURL);

        // Send the request to the AWS federation endpoint to get the sign-in token
        URLConnection conn = url.openConnection ();

        BufferedReader bufferReader = new BufferedReader(new
                InputStreamReader(conn.getInputStream()));
        String returnContent = bufferReader.readLine();

        String signinToken = new JSONObject(returnContent).getString("SigninToken");

        String signinTokenParameter = "&SigninToken=" + URLEncoder.encode(signinToken,"UTF-8");

        // The issuer parameter is optional, but recommended. Use it to direct users
        // to your sign-in page when their session expires.

        String issuerParameter = "&Issuer=" + URLEncoder.encode(ISSUER_URL, "UTF-8");

        // Finally, present the completed URL for the AWS console session to the user

        String destinationParameter = "&Destination=" + URLEncoder.encode(CONSOLE_URL,"UTF-8");
        String loginURL = SIGN_IN_URL + "?Action=login" +
                signinTokenParameter + issuerParameter + destinationParameter;


        System.out.println(loginURL);
        return loginURL;
    }

    public Credentials getCredentials(final KeycloakSecurityContext securityContext, final String roleArn) {
        return getResponse(securityContext, roleArn).credentials();
    }

    private AssumeRoleWithWebIdentityResponse getResponse(final KeycloakSecurityContext securityContext, final String roleArn) {
        AssumeRoleWithWebIdentityResponse response = stsClient.assumeRoleWithWebIdentity(request(securityContext, roleArn));
        return response;
    }

    private AssumeRoleWithWebIdentityRequest request(final KeycloakSecurityContext securityContext, final String roleArn) {

        int duration = AWS_DEFAULT_STS_DURATION;

        if(roleArn.startsWith("arn:aws:iam::")) {
            String roleName = roleArn.split("/")[1];
            GetRoleResponse response = getRole(roleName);
            duration = response.role().maxSessionDuration();
        }

        return AssumeRoleWithWebIdentityRequest.builder().roleArn(roleArn)
                .roleSessionName(securityContext.getIdToken().getPreferredUsername())
                .webIdentityToken(securityContext.getIdTokenString())
                .durationSeconds(duration).build();
    }

    private GetRoleResponse getRole(final String roleArn) {
        GetRoleRequest request = GetRoleRequest.builder()
                .roleName(roleArn)
                .build();
        return iamClient.getRole(request);
    }

}
