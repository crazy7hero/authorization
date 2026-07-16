// machine_id.h
#ifndef MACHINE_ID_H
#define MACHINE_ID_H

#include <string>

namespace MachineId {

// 获取硬件指纹（原始组合格式）
std::string GetHardwareId();

// 获取硬件指纹（SHA-256 哈希，推荐用于授权）
std::string GetHashedHardwareId();

// 检查是否在虚拟机中运行
bool IsRunningInVM();

// 检查指纹是否有效（至少采集到 2 个以上硬件信息）
bool IsValid();

// 获取采集到的组件数量
int GetComponentCount();

// 设置持久化存储路径（可选，用于 fallback ID）
void SetPersistentStoragePath(const std::string& path);

}  // namespace MachineId

#endif