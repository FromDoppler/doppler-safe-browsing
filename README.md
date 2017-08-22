# safe-browsing

A .NET implementation of [Google Safe Browsing Update API](https://developers.google.com/safe-browsing/v4/update-api) (or another alternative API).

Nuget package available at [MakingSense.SafeBrowsing](https://preview.nuget.org/packages/MakingSense.SafeBrowsing).

### Simple regex URL checker

By the moment, it is only available a naive implementation based on a downloadable regular expression blacklist.

Sample code:


**Inicialization:**

```csharp
var blacklistUrl = "https://raw.githubusercontent.com/MakingSense/safe-browsing/resources/links-blacklist.txt";
var updater = new SimpleRegexRulesHttpUpdater(blacklistUrl);
updater.UpdatePeriodically(TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(10));
DIContainer.Register<IUrlChecker>(() => new SimpleRegexUrlChecker(updater.Rules));
```

**Usage:**
```csharp
var checker = DIContainer.Resolve<IUrlChecker>();
var url ="https://github.com/MakingSense";
var result = checker.Check(url);
if (!result.IsSafe)
{
    Throw new ApplicationException($"The specified URL ({result.Url} is not safe, it seems to be related to a {result.ThreatType} threat");
}
```
