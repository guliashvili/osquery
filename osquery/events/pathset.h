/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/tokenizer.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>

namespace osquery {

/**
 * It is threadsafe.
 *
 * PathSet can take any of the two policies -
 * 1. patternedPath - Path can contain pattern '%' and '%%'.
 *                    Path components containing only '%' and '%%' are supported
 *                    e.g. '/This/Path/%'.
 *                    Path components containing partial patterns are not
 *                    supported e.g. '/This/Path/xyz%' ('xyz%' will not be
 *                    treated as pattern).
 *
 * 2. resolvedPath - path is resolved before being inserted into set.
 *                   But path can match recursively.
 *
 */
class PathSet : private boost::noncopyable {
 private:
  typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
  typedef std::vector<std::string> Path;
  typedef std::vector<Path> VPath;
  static Path createPath(const std::string& str) {
    boost::char_separator<char> sep{"/"};
    tokenizer tokens(str, sep);
    Path path;

    if (str == "/") {
      path.push_back("");
    }

    for (std::string component : tokens) {
      path.push_back(std::move(component));
    }
    return path;
  }

  static VPath createVPath(const std::string& str) {
    boost::char_separator<char> sep{"/"};
    tokenizer tokens(str, sep);
    VPath vpath;
    Path path;

    if (str == "/") {
      path.push_back("");
    }

    for (std::string component : tokens) {
      if (component == "**") {
        vpath.push_back(path);
        path.push_back(std::move(component));
        break;
      }
      path.push_back(std::move(component));
    }
    vpath.push_back(std::move(path));
    return vpath;
  }

  static bool patternMatches(const Path& lhs, const Path& rhs) {
    size_t psize = (lhs.size() < rhs.size()) ? lhs.size() : rhs.size();
    unsigned ndx;
    for (ndx = 0; ndx < psize; ++ndx) {
      if (lhs[ndx] == "**" || rhs[ndx] == "**") {
        return true;
      }

      if (lhs[ndx] == "*" || rhs[ndx] == "*") {
        continue;
      }

      int rc = lhs[ndx].compare(rhs[ndx]);
      if (rc != 0) {
        return false;
      }
    }

    return (lhs.size() < rhs.size());
  }

 public:
  void insert(const std::string& str) {
    auto pattern = str;
    replaceGlobWildcards(pattern);
    auto vpath = createVPath(pattern);

    WriteLock lock(mset_lock_);
    for (auto& path : vpath) {
      paths_.push_back(std::move(path));
    }
  }

  bool find(const std::string& str) const {
    auto path = createPath(str);

    ReadLock lock(mset_lock_);
    for (const auto& pattern : paths_) {
      if (patternMatches(pattern, path)) {
        return true;
      }
    }
    return false;
  }

  void clear() {
    WriteLock lock(mset_lock_);
    paths_.clear();
  }

  bool empty() const {
    ReadLock lock(mset_lock_);
    return paths_.empty();
  }

 private:
  std::vector<Path> paths_;
  mutable Mutex mset_lock_;
};

class resolvedPath {
 public:
  struct Path {
    Path(const std::string& str, bool r = false) : path(str), recursive(r) {}
    const std::string path;
    bool recursive{false};
  };
  typedef std::vector<Path> VPath;

  struct Compare {
    bool operator()(const Path& lhs, const Path& rhs) const {
      size_t size = (lhs.path.size() < rhs.path.size()) ? lhs.path.size()
                                                        : rhs.path.size();

      int rc = lhs.path.compare(0, size, rhs.path, 0, size);

      if (rc > 0) {
        return false;
      }

      if (rc < 0) {
        return true;
      }

      if ((size < rhs.path.size() && lhs.recursive) ||
          (size < lhs.path.size() && rhs.recursive)) {
        return false;
      }

      return (lhs.path.size() < rhs.path.size());
    }
  };

  static Path createPath(const std::string& str) {
    return Path(str);
  }

  static VPath createVPath(const std::string& str) {
    bool recursive = false;
    std::string pattern(str);
    if (pattern.find("**") != std::string::npos) {
      recursive = true;
      pattern = pattern.substr(0, pattern.find("**"));
    }

    std::vector<std::string> paths;
    resolveFilePattern(pattern, paths);

    VPath vpath;
    for (const auto& path : paths) {
      vpath.push_back(Path(path, recursive));
    }
    return vpath;
  }
};

} // namespace osquery
