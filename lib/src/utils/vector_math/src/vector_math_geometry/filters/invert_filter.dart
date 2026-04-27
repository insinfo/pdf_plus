// Copyright (c) 2015, Google Inc. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

part of '../../../vector_math_geometry.dart';

class InvertFilter extends InplaceGeometryFilter {
  @override
  void filterInplace(MeshGeometry mesh) {
    // Swap all the triangle indices
    final indicies = mesh.indices!;

    for (var i = 0; i < indicies.length; i += 3) {
      final tmp = indicies[i];
      indicies[i] = indicies[i + 2];
      indicies[i + 2] = tmp;
    }

    final normals = mesh.getViewForAttrib('NORMAL');
    if (normals is Vector3List) {
      for (var i = 0; i < normals.length; ++i) {
        normals[i] = -normals[i];
      }
    }
  }
}
