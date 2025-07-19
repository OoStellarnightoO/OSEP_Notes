# OSEP_Notes

This set of notes were used for my OSEP exam taken on July 2025. 

There is probably a fair amount of overlap between the Checklist and the individual sections because the checklist was something prepared in the days leading up the my actual exam. 

| **Name**              | **Description**                                                                                       | **Link**                                                                      |
|-----------        |---------------------------                                                                                |---------------------------------------------------------------------------|
| OSEP Checklist    | A checklist of steps to consider from initial access to lateral movement and cross-domains movement       | [OSEP Checklist](https://github.com/OoStellarnightoO/OSEP_Notes/tree/main/00%20-%20OSEP%20Checklist) |
| 




## Great Resources

**Chvancooten OSEP Code Repo**
A famous and convenient repo for OSEP. This is a good starting point and is often referenced by other students and Student Mentors in the Offsec Discord channel.

[Chvancooten OSEP Code Repo](https://github.com/chvancooten/OSEP-Code-Snippets)

**Invoke-PSObfuscation**
Singlehandedly the most important tool I discovered for the OSEP. Obfuscates your powershell shellcode and gets pass OSEP AV....100% of the time if you can get the host to execute powershell scripts.
Almost feels like cheating and makes bypassing OSEP AV trivial
In particular, I made great use of the Get-ShellCode repo referred to in the repo for my powershell shellcode runner

[Invoke-PSObfuscation](https://github.com/gh0x0st/Invoke-PSObfuscation/tree/main)

**Hacker-Recipies for AD Movement and Recon**
Very useful resource for commands related to AD lateral movement. The commands that are given in Bloodhound-CE are ...not always correct. Use this website to check for both linux and windows options to abuse AD misconfigurations

[thehacker.recipes](https://www.thehacker.recipes/)

**ired-team**
Yet another great resource to reference

[ired-team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse)

### Useful Reviews to take a look at

[rootjaxk](https://rootjaxk.github.io/posts/OSEP/)

[kentosec](https://kentosec.com/2024/05/14/osep-review-in-2024/)

[fabianlim](https://fabian-lim.com/my-review-on-osep-pen-300-2024-e77e579c7a3c)

