package in.neuw.aws.openid.controller;

import in.neuw.aws.openid.model.AwsCredentialsResponse;
import in.neuw.aws.openid.model.SecuredUserDetails;
import in.neuw.aws.openid.service.AwsCredManager;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.KeycloakSecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import software.amazon.awssdk.services.sts.model.Credentials;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Karanbir Singh on 06/01/2020
 */
@Controller
@Slf4j
public class ControlRoom {

    @Autowired
    private AwsCredManager credManager;

    @GetMapping("/aws/what/can/i/assume")
    @ResponseBody
    public SecuredUserDetails getUser(final Model model, final HttpServletRequest request) {
        SecuredUserDetails securedUserDetails = configCommonAttributes(request);
        log.info("securedUserDetails are : {}", securedUserDetails);
        model.addAttribute("securityDetails", securedUserDetails);
        return securedUserDetails;
    }

    @GetMapping({"/","","/index"})
    public String indexRedirect(final HttpServletRequest request) {
        if(getKeycloakSecurityContext(request) != null) {
            return "redirect:/credentials/manager";
        }
        return "index";
    }

    @GetMapping("/credentials/manager")
    public String credentialsManager(final Model model, final HttpServletRequest request) {
        SecuredUserDetails securedUserDetails = configCommonAttributes(request);
        log.info("securedUserDetails are : {}", securedUserDetails);
        model.addAttribute("securityDetails", securedUserDetails);
        return "credentials_landing";
    }

    @GetMapping("/get/aws/sign-in/url")
    @ResponseBody
    public String getSignInUrl(final HttpServletRequest request, @RequestParam("role_arn") String selectedRoleArn) {
        return credManager.getSignInUrl(getKeycloakSecurityContext(request), selectedRoleArn);
    }

    @GetMapping("/get/aws/credentials")
    @ResponseBody
    public AwsCredentialsResponse getAwsCredentials(final HttpServletRequest request, @RequestParam("role_arn") String selectedRoleArn) {
        Credentials credentials = credManager.getCredentials(getKeycloakSecurityContext(request), selectedRoleArn);
        AwsCredentialsResponse response = new AwsCredentialsResponse();
        response.setAccessKeyId(credentials.accessKeyId());
        response.setSecretAccessKey(credentials.secretAccessKey());
        response.setExpiration(credentials.expiration());
        return response;
    }

    @GetMapping(value = "/logout")
    public String logout(final HttpServletRequest request) throws ServletException {
        request.logout();
        return "redirect:/";
    }

    private SecuredUserDetails configCommonAttributes(final HttpServletRequest request) {
        KeycloakSecurityContext securityContext = getKeycloakSecurityContext(request);
        SecuredUserDetails securedUserDetails = new SecuredUserDetails();
        securedUserDetails.setUsername(securityContext.getIdToken().getPreferredUsername());
        securedUserDetails.setArnRoles((List<String>) securityContext.getIdToken().getOtherClaims().get("roles"));

        List<String> roleNames = securedUserDetails.getArnRoles()
                .stream().filter(r->r.startsWith("arn:aws:iam::"))
                .map(r -> r.split("/")[1])
                .collect(Collectors.toList());

        securedUserDetails.setAwsRoleNames(roleNames);

        log.debug(securityContext.getTokenString());
        return securedUserDetails;
    }

    private KeycloakSecurityContext getKeycloakSecurityContext(HttpServletRequest request) {
        return (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    }

}
