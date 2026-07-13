@{
    Severity = @('Error', 'Warning')
    IncludeRules = @(
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingEmptyCatchBlock',
        'PSAvoidUsingInvokeExpression',
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingUsernameAndPasswordParams',
        'PSUseApprovedVerbs',
        'PSUseCmdletCorrectly',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUsePSCredentialType',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns'
    )
    Rules = @{
        PSUseConsistentIndentation = @{
            Enable = $true
            Kind = 'space'
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            IndentationSize = 4
        }
    }
}
