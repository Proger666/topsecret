## Disclaimer aka expectations management
Cybersecurity strategy is a broad topic that can be approached from business, technical, or combined perspectives. It requires extensive planning and cross-team collaboration. Due to time constraints and complexity of such task, I will try to highlight the major milestones in creating such a strategy. 
The strategy does not cover aspects of fraud prevention within the scope of cybersecurity.


# Strategy major goals
- Define the future state of Information Security and align it with the company's long-term goals and development strategy; establish Information Security's role in organizational processes.
- Specify requirements for IT infrastructure from a cybersecurity perspective.
- Inventory the company's IT systems, categorizing them according to business priorities and mission. Implement a unified cybersecurity approach to manage shadow (unknown) IT systems.
- Identify a batch of essential cybersecurity projects for implementation.
- Estimate future investment needs in Cybersecurity.
- Develop employee cybersecurity training and certification programs.
- Pre-allocate necessary resources to execute the strategy effectively.
- Mitigate cybersecurity risks for the company and minimize the likelihood of fines due to data breaches or non-compliance.
- Ensure compliance with relevant standards, such as PCI-DSS and ISO 27000.


### Priorities overview

1. **Team formation**: Establish the composition of the team for ongoing cybersecurity projects. Define roles, responsibilities, and tasks. Develop a framework for problem-solving. Involve C-level executives and team leaders in this process to alleviate resistance and ensure seamless implementation of the IS strategy.

2. **Risk assessment**: Assess the organization's assets, data, and processes. Create a threat model for both external and internal actors to identify potential attack vectors and threats.

3. **Security policy development**: Formulate comprehensive security policies addressing identified risks. These policies should include user access controls, data protection protocols, incident response procedures, and acceptable use policies. Aim to unify the cybersecurity approach across the company.

4. **Integration with business processes**:
Ensure that the cybersecurity strategy is seamlessly integrated with other business processes and departments. Enforce Security Development Life Cycle (SDLC) practices across development teams. This integration should include Human Resources for employee training, Procurement for vendor management, and IT for technical implementations.

4. **Technical solutions implementation**: Deploy security solutions to guard against various threats and address major vulnerabilities. This includes setting up security appliances and integrating security tools into the company's business processes.

5. **Employee training and awareness**: Conduct training for employees on security best practices, phishing awareness, and adherence to the organization's security policies. Educate development teams about secure coding practices and modern attack methodologies.

6. **Regular audits and penetration testing**: Establish a routine for security audits and internal penetration tests using a white-box approach. This is to check for vulnerabilities and ensure compliance with security policies and best practices.

7. **Incident response plan**: Develop and routinely update an incident response plan, detailing the steps to be taken in the event of a security breach, defining roles and responsibilities, and outlining communication strategies.

8. **Third-Party penetration tests and security audits**: Schedule external security penetration tests using black-box and grey-box strategies to evaluate the overall security posture of IT infrastructure and application security.

### Required resources

#### Labor resources:
- **Cybersecurity team**: 
  - Comprises internal cybersecurity professionals such as security architects, security engineers, compliance officers, and internal penetration testers.
- **External engineers, consultants, and professional services**:
  - Third-party engineers and consultants for specialized security solutions, including vendor-assigned professional services engineers for enterprise-grade technical solutions. External penetration testers and auditors for objective security posture assessments and compliance audits.
- **Infrastructure teams**:
  - SRE/DevOps teams responsible for supporting infrastructure updates, upgrades, and changes.
- **Incident response team**:
  - An internal Security Operations Center (SOC) team tasked with incident management.
- **Project management team**:
  - Internal or external project managers to organize cybersecurity projects and ensure timely delivery.
- **Legal and compliance advisory services**:
  - To ensure that cybersecurity policies and procedures comply with relevant laws and regulations.

#### Technological resources:
- **Security software and tools**:
  - Includes SaaS security solutions, endpoint protection (EDR), next-generation firewalls (NGFW), web application firewalls (WAF/WAAP), and Security Information
- **Security software and tools**:
  - Event management (SIEM) systems, tools for secure communication, data encryption, and access management (Privileged Access Management - PAM).

- **Infrastructure resources**:
  - Compute resources in terms of CPU/RAM, virtual machines (VMs), and network intra- and interconnections.

- **Physical space**:
  - Space to accommodate physical security appliances in branches, on-premise data centers, and partner locations.

#### Training and development:
- **Employee training programs**:
  - Technological platforms for regular and updated cybersecurity awareness training for all employees, specialized training for IT and security teams on the latest cybersecurity trends and technologies, and specialized courses and workshops aligned with desired certifications.
- **Support staff training programs**:
  - Specialized training for IT support staff to handle security tool issues more effectively (excluding incident response).

#### Financial resources:
- **Budget allocation**:
  - Funding for acquiring new technologies, hiring staff, and external services, along with ongoing operational costs including software subscriptions, hardware maintenance, and employee training.
- **Cybersecurity insurance and fund**:
  - Funds allocated for acquiring cybersecurity insurance based on Protected Information (PI) data, and an additional reserve fund for critical security incidents.
### Implementation plan

#### Phase 1: Preparation and security audits
**Tasks:**
- Allocate required resources and involve necessary stakeholders.
- Define project scope, timeline, constraints, and expected outcomes.
- Negotiate project priorities with stakeholders based on business targets and goals.
- Prepare interview plans, checklists, and document templates.
- Gather information about mission/business-critical assets and processes through interviews and technical assessments.

**Outcomes:**
- Established foundation for the cybersecurity strategy.
- Comprehensive understanding of the current cybersecurity state in the organization.

#### Phase 2: Design future cybersecurity state
**Tasks:**
- Prepare a threat model for both external and internal actors.
- Design the future IS state considering business plans, threat models, and IS's role in company processes.
- Select and plan the implementation of security projects and technical solutions.
- Present and defend the cybersecurity strategy to stakeholders.
- Determine team composition and budget allocation for implementation.
- Decide on project priorities based on risk assessment and business needs.

**Outcomes:**
- Clearly defined future state of cybersecurity aligned with business goals.
- Prioritized and ready-to-implement cybersecurity projects.

#### Phase 3: Deploy and implement cybersecurity projects
**Tasks:**
- Initiate cybersecurity projects based on established priorities.
- Develop and execute testing plans.
- Coordinate project phases with the Project Manager.
- Build and demonstrate a Proof of Concept to stakeholders.
- Adjust project plans based on feedback.
- Implement solutions in phases, starting with early adopter groups.

**Outcomes:**
- Successfully deployed cybersecurity projects.
- Enhanced security measures in place, with feedback incorporated.
- Initial groups effectively using new security solutions.

#### Phase 4: Review and optimize
**Tasks:**
- Conduct a thorough review of the implemented strategies.
- Adjust plans based on feedback and evolving insights.
- Set up a regular reporting mechanism for stakeholder updates.

**Outcomes:**
- Evaluated effectiveness of the cybersecurity strategy.
- Improved and optimized cybersecurity measures.
- Continuous communication and reporting structure established.


### Example of cybersecurity projects

| Risk                                          | Cybersecurity Projects |
|-----------------------------------------------|------------------------|
| AI-Enforced Phishing and Account Takeover     | Deploy Endpoint Detection and Response (EDR) for MacOS, Linux, and Windows. Implement email security to protect Google Suite from phishing and malware. Implement password-less authentication, e.g., FIDO2. |
| Sensitive Data Leakage and Secrets Exposure   | Implement a Cloud-Native Application Protection Platform (CNAPP) for sensitive data discovery within infrastructure, container images, CI/CD pipelines, and source code. |
| Exposed Resources Exploitation and Lateral Movement | Deploy Next-Generation Web Filtering (NGWF) including Anti-Virus (AV)/Intrusion Prevention Systems (IPS) and VPN for remote branch interconnection. Deploy Web Application and API Protection (WAAP) to safeguard exposed applications and their API endpoints. |
| Malware and Ransomware                        | Deploy EDR, Email Security, CNAPP, and Next-Generation FireWall (NGFW). |
| Zero-Days and Advanced Persistent Threats (APT) | Deploy EDR and NGFW with sandboxing solutions. Implement isolated workloads based on a zero-trust architecture, restricting external network access. |
| Distributed Denial of Service (DDoS)          | Procure cloud-based DDoS mitigation solutions. |
| Data Loss/Corruption                          | Implement backup solutions for security tools and assets. |
| Supply Chain Attack                           | Deploy and integrate CNAPP for enhanced security across the supply chain. |
