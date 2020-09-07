package in.neuw.aws.openid.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

/**
 * @author Karanbir Singh on 06/01/2020
 */
@Slf4j
@Configuration
public class AwsClientsConfiguration {

    @Value("${aws.accessKeyId}")
    private String accessKeyId;

    @Value("${aws.secretAccessKey}")
    private String secretAccessKey;

    @Value("${aws.assume.role.arn}")
    private String assumeRoleARN;

    @Value("${aws.assume.role.session.name}")
    private String roleSessionName;

    @Bean
    public AwsCredentials awsCredentials() {
        AwsCredentials creds = AwsBasicCredentials.create(accessKeyId, secretAccessKey);
        return creds;
    }

    @Bean
    public AwsCredentialsProvider awsCredentialsProvider(final AwsCredentials awsCredentials) {
        return StaticCredentialsProvider.create(awsCredentials);
    }

    @Bean
    public StsClient stsClient(final AwsCredentialsProvider awsCredentialsProvider) {
        StsClient client = StsClient.builder()
                .region(Region.AP_SOUTH_1)
                .credentialsProvider(awsCredentialsProvider)
                .build();
        return client;
    }

    @Bean
    public IamClient iamClient(final AwsCredentialsProvider awsCredentialsProvider) {
        IamClient iamClient = IamClient.builder()
                .region(Region.AWS_GLOBAL)
                .credentialsProvider(awsCredentialsProvider)
                .build();
        return iamClient;
    }

    @Bean
    public AwsCredentialsProvider stsAssumeRoleCredentialsProvider(final StsClient stsClient) {
        AssumeRoleRequest assumeRoleRequest = AssumeRoleRequest.builder().roleArn(assumeRoleARN).roleSessionName(roleSessionName).build();
        StsAssumeRoleCredentialsProvider provider = StsAssumeRoleCredentialsProvider.builder().stsClient(stsClient).refreshRequest(assumeRoleRequest).build();
        return provider;
    }

    @Bean
    public IamClient iamClientAssumed(final @Qualifier("stsAssumeRoleCredentialsProvider") AwsCredentialsProvider awsCredentialsProvider) {
        return IamClient.builder().region(Region.AWS_GLOBAL).credentialsProvider(awsCredentialsProvider).build();
    }

}
