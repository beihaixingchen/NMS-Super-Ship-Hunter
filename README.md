# Super Ship Hunter / 超级飞船猎人

**Compatible with No Man's Sky 6.45.**

> **Warning:** This Mod may cause the game to crash. Back up your save before using it.

[English](#english) | [中文](#中文)

## English

Tired of endlessly hunting sentinel or exotic ships? Super Ship Hunter changes the interceptor acquisition process by injecting ship seeds directly into the game. With simple emote commands, you can immediately receive a sentinel interceptor or exotic ship matching your current system, or discover nearby dissonant systems.

### Versions

| Component | Version | Compatibility |
| --- | --- | --- |
| Game Mod | 1.4.6.45 | No Man's Sky 6.45 |
| Companion application | 1.4.6.42.1 | Verified with No Man's Sky 6.45 |

The component versions differ because the existing `1.4.6.42.1` companion application remains compatible with game version 6.45.

### Emote/Hotkey Activation

- **Local Sentinel Signal:** Locates a crashed interceptor within your current system.
- **Outsystem Sentinel Signal:** Finds a nearby, unvisited dissonant system containing interceptors.
- **Sentinel Interceptors:** Immediately offers a sentinel interceptor matching your current system.
- **Exotic:** Immediately offers an exotic ship matching your current system's seed.

### Installation

1. Create a `MODS` folder under `No Man's Sky\GAMEDATA\` if it does not already exist.
2. Download and extract the English release package.
3. Copy the entire `Super Ship Hunter 1.4.6.45` folder into `No Man's Sky\GAMEDATA\MODS\`.
4. Confirm the resulting structure is `No Man's Sky\GAMEDATA\MODS\Super Ship Hunter 1.4.6.45\METADATA\...`.
5. Start the game and load your save, then run `Super Ship Hunter V1.4.6.42.1.exe`.

To uninstall, delete the Mod folder and the executable.

### How It Works

1. Install the Mod, load your save, and run the companion application.
2. While on your freighter, use **Outsystem Sentinel Signal** to find a nearby, unvisited dissonant system.
3. Follow the green galactic route, or enter your starship and auto-warp directly to the target system.
4. Use the **Sentinel Interceptors** emote to claim that system's interceptor immediately.
5. If you do not like it, repeat step 2. If you do, keep it or use **Local Sentinel Signal** to locate a crashed one.

### Security And Memory Access

The companion application opens the `NMS.exe` process and uses Windows APIs including `ReadProcessMemory` and `WriteProcessMemory`. It scans game memory for known byte patterns, reads ship seed values, and writes those values to the Mod's ship templates. This behavior, together with PyInstaller single-file packaging, can trigger antivirus or anti-malware detections.

Review the Python source before running the application and download binaries only from this repository's [GitHub Releases](https://github.com/beihaixingchen/NMS-Super-Ship-Hunter/releases). Release notes include SHA-256 hashes for verification. An antivirus alert should not be ignored automatically; do not run the application if you are not comfortable with its memory operations.

### Q&A

**Q: What if Super Ship Hunter closes immediately after launch?**

**A:** Load your game save first. If it still closes, run the executable with Administrator privileges.

**Q: Why does antivirus software flag the tool?**

**A:** Process memory scanning/writing and PyInstaller packaging commonly trigger heuristic detections. Review the source and verify the release hash before deciding whether to allow it.

**Q: Why can I obtain an interceptor in a system that does not normally spawn sentinel ships?**

**A:** Hello Games provides interceptor seeds for every system, but enables normal interceptor spawning only in dissonant systems.

### Build From Source

Install Python, `psutil`, and PyInstaller, then run the existing build specifications from the repository root:

```powershell
python -m pip install psutil pyinstaller
pyinstaller pack-en.spec
pyinstaller pack-zh.spec
```

The executables are generated under `dist\`.

Original Nexus Mods page: [Super Ship Hunter](https://www.nexusmods.com/nomanssky/mods/3627)

---

## 中文

**适配《无人深空》6.45。**

> **警告：** 此 Mod 可能引起游戏崩溃，请先备份存档。

厌倦了传统的拦截机或异星飞船寻找方式？本模组通过直接注入飞船种子，改变飞船获取流程。使用简单的表情命令，即可立即领取与当前星系匹配的拦截机或异星飞船，也可以发现附近的不谐星系。

### 版本

| 组件 | 版本 | 兼容性 |
| --- | --- | --- |
| 游戏 Mod | 1.4.6.45 | 《无人深空》6.45 |
| 辅助程序 | 1.4.6.42.1 | 已验证兼容《无人深空》6.45 |

两个组件的版本号不同，是因为现有的 `1.4.6.42.1` 辅助程序仍然兼容游戏 6.45。

### 功能入口（表情菜单/快捷键）

- **系内拦截机信号：** 定位当前星系内坠毁的拦截机坐标。
- **系外拦截机信号：** 扫描附近未探索且含有拦截机的不谐星系。
- **护卫拦截机：** 立即获取与当前星系匹配的拦截机，可选择接受或拒绝。
- **异星：** 立即获取与当前星系种子匹配的异星飞船，可选择接受或拒绝。

### 安装指南

1. 如果游戏目录中不存在 `No Man's Sky\GAMEDATA\MODS\`，请先新建 `MODS` 文件夹。
2. 下载并解压中文发布包。
3. 将整个 `Super Ship Hunter 1.4.6.45` 文件夹复制到 `No Man's Sky\GAMEDATA\MODS\`。
4. 确认目录结构为 `No Man's Sky\GAMEDATA\MODS\Super Ship Hunter 1.4.6.45\METADATA\...`。
5. 启动游戏并载入存档，然后运行 `超级飞船猎人 V1.4.6.42.1.exe`。

卸载时，删除对应的 Mod 文件夹和 EXE 即可。

### 操作指南

1. 安装模组、载入存档，然后运行辅助程序。
2. 在货船内使用 **系外拦截机信号** 表情，扫描附近未探索的不谐星系。
3. 跟随绿色星系路线，或进入飞船自动跃迁至目标星系。
4. 使用 **护卫拦截机** 表情，立即领取该星系的拦截机。
5. 不满意可重复第 2 步；满意则可直接接受，也可以使用 **系内拦截机信号** 搜寻坠毁的拦截机。

### 安全与内存操作说明

辅助程序会打开 `NMS.exe` 进程，并使用包括 `ReadProcessMemory` 和 `WriteProcessMemory` 在内的 Windows API。程序会扫描游戏内存中的已知字节特征，读取飞船种子，并将种子写入 Mod 使用的飞船模板。此类行为加上 PyInstaller 单文件打包，可能触发杀毒软件或安全软件的启发式检测。

运行前请检查本仓库公开的 Python 源码，并仅从本仓库的 [GitHub Releases](https://github.com/beihaixingchen/NMS-Super-Ship-Hunter/releases) 下载程序。发布说明会提供 SHA-256 校验值。安全软件报警不应被自动忽略；如果你不接受此程序的内存操作方式，请不要运行。

### 常见问题

**Q：超级飞船猎人启动后立即闪退怎么办？**

**A：** 请先载入游戏存档。如果仍然闪退，请尝试以管理员身份运行 EXE。

**Q：为什么杀毒软件提示威胁？**

**A：** 进程内存扫描、写入以及 PyInstaller 打包容易触发启发式检测。请先检查源码并核对发布文件哈希，再决定是否添加信任。

**Q：为什么当前星系没有正常生成拦截机，也能通过模组获取？**

**A：** Hello Games 为每个星系都准备了拦截机种子，但只在不谐星系开放正常的拦截机生成。

### 从源码打包

安装 Python、`psutil` 和 PyInstaller，然后在仓库根目录执行：

```powershell
python -m pip install psutil pyinstaller
pyinstaller pack-en.spec
pyinstaller pack-zh.spec
```

生成的 EXE 位于 `dist\` 目录。

原 Nexus Mods 页面：[超级飞船猎人](https://www.nexusmods.com/nomanssky/mods/3627)

## License

The source code is available under the [MIT License](LICENSE).
