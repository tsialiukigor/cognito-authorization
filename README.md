# Cognito authorization service

The idea is to authorize users using Cognito service, add users to groups with different credentials, and use a custom authorizer to verify the coming JWT token that it's valid and decode it to check the groups. Group in authorizer function is hardcoded as there is no way to pass arguments to the authorizer.
