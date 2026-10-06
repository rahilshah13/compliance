const cdk = require('aws-cdk-lib');
const ec2 = require('aws-cdk-lib/aws-ec2');
const iam = require('aws-cdk-lib/aws-iam');
const fs = require('fs');
const path = require('path');

class CdkStack extends cdk.Stack {
  /**
   * @param {cdk.App} scope
   * @param {string} id
   * @param {cdk.StackProps=} props
   */
  constructor(scope, id, props) {
    super(scope, id, props);

    // 1. Create base VPC (IPv4)
    const vpc = new ec2.CfnVPC(this, 'CustomVPC', {
      cidrBlock: '10.0.0.0/16',
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    // 2. Associate your BYOIP IPv6 IPAM Pool to the VPC
    const vpcIpv6Cidr = new ec2.CfnVPCCidrBlock(this, 'VpcIpv6Cidr', {
      vpcId: vpc.ref,
      ipv6IpamPoolId: 'ipam-pool-0758869f62242c7e9',
      ipv6NetmaskLength: 56,
    });

    // 3. Internet Gateway and Route Table setup for IPv4 & IPv6
    const igw = new ec2.CfnInternetGateway(this, 'InternetGateway');
    const igwAttachment = new ec2.CfnVPCGatewayAttachment(this, 'IgwAttachment', {
      vpcId: vpc.ref,
      internetGatewayId: igw.ref,
    });

    const routeTable = new ec2.CfnRouteTable(this, 'PublicRouteTable', {
      vpcId: vpc.ref,
    });

    const ipv4Route = new ec2.CfnRoute(this, 'Ipv4Route', {
      routeTableId: routeTable.ref,
      destinationCidrBlock: '0.0.0.0/0',
      gatewayId: igw.ref,
    });
    ipv4Route.addDependency(igwAttachment);

    const ipv6Route = new ec2.CfnRoute(this, 'Ipv6Route', {
      routeTableId: routeTable.ref,
      destinationIpv6CidrBlock: '::/0',
      gatewayId: igw.ref,
    });
    ipv6Route.addDependency(igwAttachment);
    ipv6Route.addDependency(vpcIpv6Cidr);

    // 4. Public Subnet explicitly pulling a /64 block from the VPC's IPv6 range via Fn::Cidr
    const subnet = new ec2.CfnSubnet(this, 'PublicSubnet', {
      vpcId: vpc.ref,
      cidrBlock: '10.0.1.0/24',
      availabilityZone: `${this.region}a`,
      assignIpv6AddressOnCreation: true,
      ipv6CidrBlock: cdk.Fn.select(
        0,
        cdk.Fn.cidr(
          cdk.Fn.select(0, vpc.attrIpv6CidrBlocks),
          256,
          '64'
        )
      ),
      mapPublicIpOnLaunch: true,
    });
    subnet.addDependency(vpcIpv6Cidr);

    const subnetRouteTableAssociation = new ec2.CfnSubnetRouteTableAssociation(this, 'SubnetRTA', {
      subnetId: subnet.ref,
      routeTableId: routeTable.ref,
    });

    // 5. Security Group allowing HTTP and SSH traffic
    const securityGroup = new ec2.SecurityGroup(this, 'InstanceSecurityGroup', {
      vpc: ec2.Vpc.fromVpcAttributes(this, 'ImportedVpc', {
        vpcId: vpc.ref,
        availabilityZones: [subnet.availabilityZone],
        publicSubnetIds: [subnet.ref],
        publicSubnetRouteTableIds: [routeTable.ref],
      }),
      allowAllOutbound: true,
      description: 'Security group for Docker Compose EC2 instance',
    });

    securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP IPv4');
    securityGroup.addIngressRule(ec2.Peer.anyIpv6(), ec2.Port.tcp(80), 'Allow HTTP IPv6');
    securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH');

    // 6. IAM Role for EC2 Instance management (SSM)
    const role = new iam.Role(this, 'Ec2InstanceRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    });

    // 7. User Data Script to Bootstrap Docker, Docker Compose, and source repo files
    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      'yum update -y',
      'yum install -y docker git',
      'systemctl start docker',
      'systemctl enable docker',
      'mkdir -p /usr/local/lib/docker/cli-plugins',
      'curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose',
      'chmod +x /usr/local/lib/docker/cli-plugins/docker-compose',
      'mkdir -p /app',
      'cd /app'
    );

    const sourceDir = path.join(__dirname, '..');
    ['docker-compose.yml', 'app.py', 'index.html'].forEach((file) => {
      const filePath = path.join(sourceDir, file);
      if (fs.existsSync(filePath)) {
        const fileContent = fs.readFileSync(filePath, 'utf8');
        if (fileContent.length < 15000) {
          userData.addCommands(`cat << 'EOF' > /app/${file}\n${fileContent}\nEOF`);
        }
      }
    });

    userData.addCommands('docker compose up -d');

    // 8. EC2 Instance Definition
    const instance = new ec2.Instance(this, 'DockerInstance', {
      vpc: ec2.Vpc.fromVpcAttributes(this, 'VpcRef', {
        vpcId: vpc.ref,
        availabilityZones: [subnet.availabilityZone],
        publicSubnetIds: [subnet.ref],
        publicSubnetRouteTableIds: [routeTable.ref],
      }),
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      securityGroup: securityGroup,
      role: role,
      userData: userData,
    });

    instance.node.addDependency(subnetRouteTableAssociation);

    // 9. Outputs
    new cdk.CfnOutput(this, 'InstanceId', {
      value: instance.instanceId,
      description: 'The EC2 Instance ID',
    });

    new cdk.CfnOutput(this, 'InstancePublicIpv6', {
      value: instance.instanceIpv6Addresses[0],
      description: 'The primary public IPv6 address of the EC2 instance',
    });
  }
}

module.exports = { CdkStack };