package main

import (
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/lambda"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/secretsmanager"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.New(ctx, "myapp")
		bucketName := cfg.Require("bucketName")
		functionName := cfg.Require("functionName")
		secretName := cfg.Require("secretName")

		secret, err := createSecretManager(ctx, "appSecret", secretName)
		if err != nil {
			return err
		}

		// Create the S3 Bucket
		bucket, err := createSecureBucket(ctx, "secureBucket", bucketName)
		if err != nil {
			return err
		}

		// Disable Public Access
		err = disablePublicAccess(ctx, bucket.ID())
		if err != nil {
			return err
		}

		// Enable Data At-Rest Encryption (AES256)
		err = enableEncryption(ctx, bucket.ID(), "AES256")
		if err != nil {
			return err
		}

		// Enforce Data In-Transit Encryption (TLS/HTTPS via Policy)
		err = enforceTlsPolicy(ctx, bucket.Arn)
		if err != nil {
			return err
		}

		lambdaRole, err := createLambdaRole(ctx, "lambdaRole")
		if err != nil {
			return err
		}

		fn, err := secureLambdaFunctionUrl(ctx, "secureFunction", functionName, lambdaRole.Arn)
		if err != nil {
			return err
		}

		funcUrl, err := createLambdaFunction(ctx, "secureFunctionUrl", functionName, lambdaRole.Arn)
		if err != nil {
			return err
		}

		// Export Stack Outputs
		ctx.Export("bucketName", bucket.ID())
		ctx.Export("bucketArn", bucket.Arn)
		ctx.Export("secretArn", secret.Arn)
		ctx.Export("functionUrl", funcUrl)

		return nil
	})
}

func createSecretManager(ctx *pulumi.Context, resourceName string, secretName string) (*secretsmanager.Secret, error) {
	return secretsmanager.NewSecret(ctx, resourceName, &secretsmanager.SecretArgs{
		Name: pulumi.String(secretName),
	})
}

func createSecureBucket(ctx *pulumi.Context, resourceName string, bucketName string) (*s3.Bucket, error) {
	return s3.NewBucket(ctx, resourceName, &s3.BucketArgs{
		Bucket: pulumi.String(bucketName),
	})
}

func disablePublicAccess(ctx *pulumi.Context, bucketID pulumi.StringInput) error {
	_, err := s3.NewBucketPublicAccessBlock(ctx, "publicAccessBlock", &s3.BucketPublicAccessBlockArgs{
		Bucket:                bucketID,
		BlockPublicAcls:       pulumi.Bool(true),
		BlockPublicPolicy:     pulumi.Bool(true),
		IgnorePublicAcls:      pulumi.Bool(true),
		RestrictPublicBuckets: pulumi.Bool(true),
	})
	return err
}

func enableEncryption(ctx *pulumi.Context, bucketID pulumi.StringInput, algorithm string) error {
	_, err := s3.NewBucketServerSideEncryptionConfigurationV2(ctx, "encryptionConfig", &s3.BucketServerSideEncryptionConfigurationV2Args{
		Bucket: bucketID,
		Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
			&s3.BucketServerSideEncryptionConfigurationV2RuleArgs{
				ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
					SseAlgorithm: pulumi.String(algorithm),
				},
			},
		},
	})
	return err
}

func enforceTlsPolicy(ctx *pulumi.Context, bucketArn pulumi.StringOutput) error {
	policyDoc := pulumi.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"EnforceTLSRequestsOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["%s","%s/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, bucketArn, bucketArn)

	bucketName := bucketArn.ApplyT(func(arn string) string {
		parts := strings.Split(arn, ":")
		if len(parts) > 5 {
			return parts[5]
		}
		return arn
	}).(pulumi.StringInput)

	_, err := s3.NewBucketPolicy(ctx, "bucketPolicy", &s3.BucketPolicyArgs{
		Bucket: bucketName,
		Policy: policyDoc,
	})
	return err
}

func createLambdaRole(ctx *pulumi.Context, resourceName string) (*iam.Role, error) {
	assumeRolePolicy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
		Statements: []iam.GetPolicyDocumentStatement{
			{
				Actions: []string{"sts:AssumeRole"},
				Principals: []iam.GetPolicyDocumentStatementPrincipal{
					{
						Type:        "Service",
						Identifiers: []string{"lambda.amazonaws.com"},
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return iam.NewRole(ctx, resourceName, &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(assumeRolePolicy.Json),
	})
}

func secureLambdaFunctionUrl(ctx *pulumi.Context, resourceName string, functionName string, roleArn pulumi.StringOutput) (*lambda.Function, error) {
	return lambda.NewFunction(ctx, resourceName, &lambda.FunctionArgs{
		Name:    pulumi.String(functionName),
		Runtime: pulumi.String("provided.al2023"),
		Role:    roleArn,
		Handler: pulumi.String("bootstrap"),
		Code:    pulumi.NewFileArchive("./lambda.zip"),
	})
}

func createLambdaFunction(ctx *pulumi.Context, resourceName string, functionName string, roleArn pulumi.StringOutput) (pulumi.StringOutput, error) {
	fn, err := lambda.NewFunction(ctx, resourceName, &lambda.FunctionArgs{
		Name:    pulumi.String(functionName),
		Runtime: pulumi.String("provided.al2023"),
		Role:    roleArn,
		Handler: pulumi.String("bootstrap"),
		Code:    pulumi.NewFileArchive("./lambda.zip"),
	})
	if err != nil {
		return pulumi.StringOutput{}, err
	}

	funcUrl, err := lambda.NewFunctionUrl(ctx, resourceName+"Url", &lambda.FunctionUrlArgs{
		FunctionName:      fn.Name,
		AuthorizationType: pulumi.String("AWS_IAM"),
	})
	if err != nil {
		return pulumi.StringOutput{}, err
	}

	return funcUrl.FunctionUrl, nil
}
