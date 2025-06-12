Recently uncovered details shed light on the operational strategy of Stuxbot's newest iteration.
1. The newest iterations of Stuxbot are exploiting the `C:\Users\Public` directory as a conduit for deploying supplementary utilities.
2. The newest iterations of Stuxbot are utilizing registry run keys as a mechanism to ensure their sustained presence within the infected system.
3. The newest iterations of Stuxbot are utilizing PowerShell Remoting for lateral movement within the network and to gain access to domain controllers.
## The Tasks
---
`Hunt 1`: Create a KQL query to hunt for ["Lateral Tool Transfer"](https://attack.mitre.org/techniques/T1570/) to `C:\Users\Public`. Enter the content of the `user.name` field in the document that is related to a transferred tool that starts with "r" as your answer.

![](../../../Image/Pasted%20image%2020250415000546.png)

`Hunt 2`: Create a KQL query to hunt for ["Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"](https://attack.mitre.org/techniques/T1547/001/). Enter the content of the `registry.value` field in the document that is related to the first registry-based persistence action as your answer.

![](../../../Image/Pasted%20image%2020250415012613.png)

`Hunt 3`: Create a KQL query to hunt for ["PowerShell Remoting for Lateral Movement"](https://www.ired.team/offensive-security/lateral-movement/t1028-winrm-for-lateral-movement). Enter the content of the `winlog.user.name` field in the document that is related to PowerShell remoting-based lateral movement towards DC1.

![](../../../Image/Pasted%20image%2020250415023204.png)

- `message : "*Enter-PSSession*"`

![](../../../Image/Pasted%20image%2020250415023021.png)