[Operational Technology (OT)](Operational%20Technology%20(OT).md) refers to systems used to monitor and control industrial operations. Industrial [Control Systems (ICS)](Control%20Systems%20(ICS).md) includes systems used to monitor and control industrial processes.

If IT operators have dozens of years of experience securing networks, systems and applications, OT operators are pretty new to this topic. Moreover in OT/ICS development availability is always preferred over integrity and confidentiality. In other words ICS softwares are designed to be fast but, often, insecure.

Supervisory Control and Data Acquisition (SCADA) systems are used to control and automate industrial processes. SCADA systems includes:

- Supervisory computers: the servers used to manage the process gathering data on the process and communicating with filed devices (PLC/RTU). In smaller deployments HMI is embedded in a single computer, in larger deploy HMI is installed into a dedicated computer.
    
- Programmable Logic Controllers (PLC): digital computers used mainly for automating industrial processes. They are used to continuously monitor sensors (input) and make decisions controlling devices (output).
    
- Remote Terminal Units (RTU): nowadays RTUs and PLCs functionalities overlap with each other. RTUs are usually preferred for wider geographical telemetry whereas PLCs are better with local controls.
    
- Communication network: the network connecting all SCADA components (Ethernet, Serial, telephones, radio, cellular...). Network failures do not necessarily impact negatively on the plant process.  Both RTU's and PLC's should be designed to operate autonomously, using the last instruction given from the supervisory system.
    
- Human Machine Interface (HMI): displays a digitalized representation of the plant. Operators can interact with the plant issuing commands using mouse, keyboards or touch screens. Operators can make supervisory decisions adjusting or overriding the normal plant behaviour.
    

In short and simple words:

- industries are managed by sophisticated, mission critical computers (SCADA systems);
    
- security is not the first priority in OT/ICS;
    
- operators can manually override the behaviour of the plant via mouse/keyboard/touchscreen, locally or remotely;
    
- a malicious software can override the behaviour of the plant like HMI does.
    

For more information see [Guide to Industrial Control Systems (ICS) Security (NIST 800-82)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r2.pdf).