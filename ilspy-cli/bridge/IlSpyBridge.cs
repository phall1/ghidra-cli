using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

public static class IlSpyBridge
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    // ── Helpers ──────────────────────────────────────────────────────────

    private static string ReadUtf8(IntPtr ptr, int len)
    {
        if (ptr == IntPtr.Zero || len <= 0) return string.Empty;
        unsafe
        {
            return Encoding.UTF8.GetString((byte*)ptr, len);
        }
    }

    private static IntPtr MarshalJson(object obj, out int resultLen)
    {
        string json = JsonSerializer.Serialize(obj, JsonOptions);
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        resultLen = bytes.Length;
        return ptr;
    }

    private static IntPtr MarshalError(string message, out int resultLen)
    {
        var error = new { error = message };
        return MarshalJson(error, out resultLen);
    }

    private static CSharpDecompiler CreateDecompiler(string path)
    {
        var settings = new DecompilerSettings
        {
            ThrowOnAssemblyResolveErrors = false
        };
        return new CSharpDecompiler(path, settings);
    }

    // ── Exports ──────────────────────────────────────────────────────────

    [UnmanagedCallersOnly(EntryPoint = "ListTypes")]
    public static IntPtr ListTypes(IntPtr pathPtr, int pathLen, IntPtr resultLenPtr)
    {
        int resultLen = 0;
        try
        {
            var path = ReadUtf8(pathPtr, pathLen);
            var decompiler = CreateDecompiler(path);

            var types = decompiler.TypeSystem.MainModule.TypeDefinitions
                .Where(t => !t.Name.StartsWith("<"))
                .Select(t => new
                {
                    fullName = t.FullName,
                    ns = t.Namespace,
                    name = t.Name,
                    kind = t.Kind.ToString(),
                    methodCount = t.Methods.Count(),
                    propertyCount = t.Properties.Count(),
                    fieldCount = t.Fields.Count(),
                    isPublic = t.Accessibility == Accessibility.Public
                })
                .OrderBy(t => t.fullName)
                .ToList();

            var ptr = MarshalJson(types, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
        catch (Exception ex)
        {
            var ptr = MarshalError(ex.Message, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "ListMethods")]
    public static IntPtr ListMethods(IntPtr pathPtr, int pathLen,
                                      IntPtr typePtr, int typeLen,
                                      IntPtr resultLenPtr)
    {
        int resultLen = 0;
        try
        {
            var path = ReadUtf8(pathPtr, pathLen);
            var typeName = ReadUtf8(typePtr, typeLen);
            var decompiler = CreateDecompiler(path);

            IEnumerable<ITypeDefinition> typeDefs;
            if (string.IsNullOrEmpty(typeName))
            {
                typeDefs = decompiler.TypeSystem.MainModule.TypeDefinitions;
            }
            else
            {
                var type = decompiler.TypeSystem.FindType(new FullTypeName(typeName)) as ITypeDefinition;
                if (type == null)
                {
                    var ptr2 = MarshalError($"Type not found: {typeName}", out resultLen);
                    Marshal.WriteInt32(resultLenPtr, resultLen);
                    return ptr2;
                }
                typeDefs = new[] { type };
            }

            var methods = typeDefs
                .SelectMany(t => t.Methods)
                .Where(m => !m.Name.StartsWith("<"))
                .Select(m => new
                {
                    typeName = m.DeclaringType.FullName,
                    name = m.Name,
                    returnType = m.ReturnType.FullName,
                    parameters = m.Parameters.Select(p => new
                    {
                        name = p.Name,
                        type = p.Type.FullName
                    }).ToList(),
                    accessibility = m.Accessibility.ToString(),
                    isStatic = m.IsStatic,
                    isVirtual = m.IsVirtual,
                    isAbstract = m.IsAbstract
                })
                .OrderBy(m => m.typeName)
                .ThenBy(m => m.name)
                .ToList();

            var ptr = MarshalJson(methods, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
        catch (Exception ex)
        {
            var ptr = MarshalError(ex.Message, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "DecompileType")]
    public static IntPtr DecompileType(IntPtr pathPtr, int pathLen,
                                        IntPtr typePtr, int typeLen,
                                        IntPtr resultLenPtr)
    {
        int resultLen = 0;
        try
        {
            var path = ReadUtf8(pathPtr, pathLen);
            var typeName = ReadUtf8(typePtr, typeLen);
            var decompiler = CreateDecompiler(path);

            var type = decompiler.TypeSystem.FindType(new FullTypeName(typeName)) as ITypeDefinition;
            if (type == null)
            {
                var ptr2 = MarshalError($"Type not found: {typeName}", out resultLen);
                Marshal.WriteInt32(resultLenPtr, resultLen);
                return ptr2;
            }

            var fullTypeName = new FullTypeName(typeName);
            var source = decompiler.DecompileTypeAsString(fullTypeName);

            var ptr = MarshalJson(new { source, typeName = type.FullName }, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
        catch (Exception ex)
        {
            var ptr = MarshalError(ex.Message, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "DecompileMethod")]
    public static IntPtr DecompileMethod(IntPtr pathPtr, int pathLen,
                                          IntPtr typePtr, int typeLen,
                                          IntPtr methodPtr, int methodLen,
                                          IntPtr resultLenPtr)
    {
        int resultLen = 0;
        try
        {
            var path = ReadUtf8(pathPtr, pathLen);
            var typeName = ReadUtf8(typePtr, typeLen);
            var methodName = ReadUtf8(methodPtr, methodLen);
            var decompiler = CreateDecompiler(path);

            var type = decompiler.TypeSystem.FindType(new FullTypeName(typeName)) as ITypeDefinition;
            if (type == null)
            {
                var ptr2 = MarshalError($"Type not found: {typeName}", out resultLen);
                Marshal.WriteInt32(resultLenPtr, resultLen);
                return ptr2;
            }

            var method = type.Methods.FirstOrDefault(m => m.Name == methodName);
            if (method == null)
            {
                var ptr2 = MarshalError($"Method not found: {methodName} on type {typeName}", out resultLen);
                Marshal.WriteInt32(resultLenPtr, resultLen);
                return ptr2;
            }

            var handle = (MethodDefinitionHandle)method.MetadataToken;

            // Decompile just this method by decompiling the type and extracting
            // (ICSharpCode.Decompiler doesn't have a direct single-method-to-string)
            var syntaxTree = decompiler.Decompile(handle);
            var source = syntaxTree.ToString();

            var ptr = MarshalJson(new
            {
                source,
                typeName = type.FullName,
                methodName = method.Name,
                returnType = method.ReturnType.FullName
            }, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
        catch (Exception ex)
        {
            var ptr = MarshalError(ex.Message, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "DecompileFull")]
    public static IntPtr DecompileFull(IntPtr pathPtr, int pathLen, IntPtr resultLenPtr)
    {
        int resultLen = 0;
        try
        {
            var path = ReadUtf8(pathPtr, pathLen);
            var decompiler = CreateDecompiler(path);
            var source = decompiler.DecompileWholeModuleAsString();

            var ptr = MarshalJson(new { source }, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
        catch (Exception ex)
        {
            var ptr = MarshalError(ex.Message, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "GetAssemblyInfo")]
    public static IntPtr GetAssemblyInfo(IntPtr pathPtr, int pathLen, IntPtr resultLenPtr)
    {
        int resultLen = 0;
        try
        {
            var path = ReadUtf8(pathPtr, pathLen);
            var decompiler = CreateDecompiler(path);
            var module = decompiler.TypeSystem.MainModule;

            var peFile = module.MetadataFile as PEFile;
            string targetFw = "";
            var refsList = new List<object>();

            if (peFile != null)
            {
                targetFw = peFile.DetectTargetFrameworkId() ?? "";
                refsList = peFile.AssemblyReferences
                    .Select(r => new { name = r.Name, version = r.Version.ToString() } as object)
                    .OrderBy(r => r.ToString())
                    .ToList();
            }

            var info = new
            {
                name = module.AssemblyName,
                typeCount = module.TypeDefinitions.Count(),
                targetFramework = targetFw,
                references = refsList
            };

            var ptr = MarshalJson(info, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
        catch (Exception ex)
        {
            var ptr = MarshalError(ex.Message, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "SearchSource")]
    public static IntPtr SearchSource(IntPtr pathPtr, int pathLen,
                                       IntPtr patternPtr, int patternLen,
                                       IntPtr resultLenPtr)
    {
        int resultLen = 0;
        try
        {
            var path = ReadUtf8(pathPtr, pathLen);
            var pattern = ReadUtf8(patternPtr, patternLen);
            var decompiler = CreateDecompiler(path);

            var regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            var results = new List<object>();

            foreach (var typeDef in decompiler.TypeSystem.MainModule.TypeDefinitions)
            {
                if (typeDef.Name.StartsWith("<")) continue;

                try
                {
                    var fullName = new FullTypeName(typeDef.FullName);
                    var source = decompiler.DecompileTypeAsString(fullName);
                    var matches = regex.Matches(source);

                    if (matches.Count > 0)
                    {
                        var lines = source.Split('\n');
                        var matchInfos = new List<object>();

                        foreach (Match match in matches)
                        {
                            // Find line number of match
                            int charCount = 0;
                            int lineNum = 0;
                            for (int i = 0; i < lines.Length; i++)
                            {
                                if (charCount + lines[i].Length >= match.Index)
                                {
                                    lineNum = i + 1;
                                    break;
                                }
                                charCount += lines[i].Length + 1; // +1 for \n
                            }

                            // Context: line before, match line, line after
                            int start = Math.Max(0, lineNum - 2);
                            int end = Math.Min(lines.Length - 1, lineNum);
                            var context = string.Join("\n",
                                lines.Skip(start).Take(end - start + 1)
                                     .Select(l => l.TrimEnd()));

                            matchInfos.Add(new
                            {
                                line = lineNum,
                                matched = match.Value,
                                context
                            });
                        }

                        results.Add(new
                        {
                            typeName = typeDef.FullName,
                            matchCount = matches.Count,
                            matches = matchInfos
                        });
                    }
                }
                catch
                {
                    // Skip types that fail to decompile
                }
            }

            var ptr = MarshalJson(results, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
        catch (Exception ex)
        {
            var ptr = MarshalError(ex.Message, out resultLen);
            Marshal.WriteInt32(resultLenPtr, resultLen);
            return ptr;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "FreeMem")]
    public static void FreeMem(IntPtr ptr)
    {
        if (ptr != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(ptr);
        }
    }
}
