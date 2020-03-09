# CS161 Reading Notes

### Principals for building secure systems

Security is economics - It doesn't make sense to spend a ton of money securing a system that wasn't expensive and doesn't pose any other threat. 

Least privilege - Give each component enough privilege to do what it needs to do but nothing more. It reduces the damage done if a program is subverted

Use fail-safe failures - when something breaks, it defaults to secure behavior. Things have to be white listed because everything is banned by default. 

Seperation of responsibility - Make it such that both things must fail for security to be compromised. 

Defense in depth - Pretty much the same thing in a more general phrasing 

Psychologic acceptance - You need the people working with the system to accept it, it the people its meant to protect are trying to subvert it, its gonna fail

Human factors - Make it so that people can use it. If it is confusing or annoying people are just going to ignore it completely 

Ensure complete mediation - You need to check every access point to everything you are trying to protect. 

Know your threat model - Systems are often built with some assumptions in mind. You have to be aware of these so that you can take action if something changes. 

Detect if you can't prevent - pretty self evident. Even if something goes wrong you want to know who did it. 

Don't rely on security through obscurity - Like it might work for a while but when it breaks it breaks hard. This is brittle and its harder than you think to keep something obscure. 

Design security from the start - Its very hard to retro fit code that has security issues, escpecially if the design is susceptible to attack. 

Conservitive design - When measuring how vulnerable a system is, consider it under optimal conditions for the attacker. Assume the worst case and prepare as much as possible.

Kerkhoff’s principle - The system should remain secure even when the attacker knows the system. Literally the reason not one but two death stars were destroyed. 

Proactively study attacks - Try to break your own stuff. You defiantly want to know if something is vulnerable before anyone else. 



### Design patterns for secure systems

The **Trusted Computing Base (TCB)** is part of the system that we can rely on to behave. In any system, the TCB must operate correctly or the system just isn't secure. We must be able to rely on every part of the TCB but at the same time not rely on anything outside the TCB. It by definition must be large enough so than nothing outside the TCB can defeat the system. Some components are almost always in the TCB, for example, the OS, CPU and compilers kinda have to be trusted. For access control problems, the refrence monitor (thing that actually grants access) has to be part of the TCB. 

TCB design principals:

- Know what is in the TCB. Design your system so that the TCB is clearly identifiable.

- Try to make the TCB unbypassable, tamper-resistant, and as verifiable as possible.
- Keep It Simple, Stupid (KISS). The simpler the TCB, the greater the chances you can get it right.  
- Decompose for security. Choose a system decomposition/modularization based not just on functionality or performance grounds—choose an architecture that makes the TCB as simple and clear as possible.

#### TOCTTOU Vulnerabilities

```c++
int openregularfile(char *path) {
	struct stat s;
	if (stat(path, &s) < 0)
		return -1;
	if (!S_ISRREG(s.st_mode)) {
		error("only allowed to open regular files; nice try!");
		return -1;
	}
	return open(path, O_RDONLY);
}
```

This code is trying to open a file, but only if its a normal file. The stat() function is used to extract metadata about a file including if its regular or not. The assumption of the code is that the state of the machine and filesystem will remain the same between the stat() call and the open() call. This may ot be the case if there is code running concurrently. If a hacker was able to change the file path after the stat() call but before the file is opened then they could access a document they shouldn't be able to. TOCTTOU stands for *Time of check to time of use*. This can be an issue for any application where there is concurrent access to the same thing.

