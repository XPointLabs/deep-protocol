namespace Deep.Protocol.Tests.DeepNative;

/// <summary>
/// Full public DRM20 first-deployment regression. It is intentionally not mapped as
/// package evidence because durable final-reread callbacks exceed the closed vector budget.
/// </summary>
public sealed class GenesisFullDagEvidenceTests
{
    [Fact]
    public async Task PublicDrm20FirstDeployment_ReachesLocalCommittedWithDurableRereads()
    {
        await new DeploymentGovernanceOriginTests()
            .FirstDeployment_PublicPath_ReachesLocalCommittedThroughExactThreeWitnesses();
    }
}
