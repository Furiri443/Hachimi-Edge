use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::c_void;
use objc2::{msg_send, sel, runtime::AnyObject};
use crate::core::Error;

#[repr(transparent)]
pub struct MetalObject(pub *mut AnyObject);
unsafe impl Send for MetalObject {}
unsafe impl Sync for MetalObject {}

impl Drop for MetalObject {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                let _: () = objc2::msg_send![self.0, release];
            }
        }
    }
}

fn ns_string(s: &str) -> *mut AnyObject {
    unsafe {
        let c_str = CString::new(s).unwrap();
        let cls = objc2::class!(NSString);
        let str_obj: *mut AnyObject = msg_send![cls, alloc];
        msg_send![str_obj, initWithUTF8String: c_str.as_ptr()]
    }
}

const SHADER_SOURCE: &str = r#"
    #include <metal_stdlib>
    using namespace metal;

    struct VertexIn {
        float2 position [[attribute(0)]];
        float2 uv [[attribute(1)]];
        uchar4 color [[attribute(2)]];
    };

    struct VertexOut {
        float4 position [[position]];
        float2 uv;
        float4 color;
    };

    struct Uniforms {
        float2 screen_size;
    };

    vertex VertexOut vertex_main(VertexIn in [[stage_in]], constant Uniforms &uniforms [[buffer(1)]]) {
        VertexOut out;
        out.position = float4(
            2.0 * in.position.x / uniforms.screen_size.x - 1.0,
            1.0 - 2.0 * in.position.y / uniforms.screen_size.y,
            0.0,
            1.0
        );
        out.uv = in.uv;
        out.color = float4(in.color) / 255.0;
        return out;
    }

    fragment float4 fragment_main(VertexOut in [[stage_in]], texture2d<float> tex [[texture(0)]], sampler s [[sampler(0)]]) {
        return in.color * tex.sample(s, in.uv);
    }
"#;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MTLOrigin {
    pub x: usize,
    pub y: usize,
    pub z: usize,
}

unsafe impl objc2::Encode for MTLOrigin {
    const ENCODING: objc2::Encoding = objc2::Encoding::Struct(
        "?",
        &[usize::ENCODING, usize::ENCODING, usize::ENCODING],
    );
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MTLSize {
    pub width: usize,
    pub height: usize,
    pub depth: usize,
}

unsafe impl objc2::Encode for MTLSize {
    const ENCODING: objc2::Encoding = objc2::Encoding::Struct(
        "?",
        &[usize::ENCODING, usize::ENCODING, usize::ENCODING],
    );
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MTLRegion {
    pub origin: MTLOrigin,
    pub size: MTLSize,
}

unsafe impl objc2::Encode for MTLRegion {
    const ENCODING: objc2::Encoding = objc2::Encoding::Struct(
        "?",
        &[MTLOrigin::ENCODING, MTLSize::ENCODING],
    );
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MTLScissorRect {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}

unsafe impl objc2::Encode for MTLScissorRect {
    const ENCODING: objc2::Encoding = objc2::Encoding::Struct(
        "?",
        &[usize::ENCODING, usize::ENCODING, usize::ENCODING, usize::ENCODING],
    );
}


pub struct MetalPainter {
    pipeline_state: MetalObject,
    sampler: MetalObject,
    textures: HashMap<egui::TextureId, MetalObject>,
}

impl MetalPainter {
    pub fn new(device: *mut AnyObject) -> Result<Self, Error> {
        unsafe {
            let source_ns = ns_string(SHADER_SOURCE);
            let library: *mut AnyObject = msg_send![device, newLibraryWithSource: source_ns, options: std::ptr::null_mut::<AnyObject>(), error: std::ptr::null_mut::<*mut AnyObject>()];
            if library.is_null() {
                error!("iOS GUI Metal: newLibraryWithSource returned null");
                return Err(Error::RuntimeError("Metal: Shader compilation failed".into()));
            }

            let v_fn: *mut AnyObject = msg_send![library, newFunctionWithName: ns_string("vertex_main")];
            let f_fn: *mut AnyObject = msg_send![library, newFunctionWithName: ns_string("fragment_main")];
            if v_fn.is_null() || f_fn.is_null() {
                error!(
                    "iOS GUI Metal: shader function missing vertex={:p} fragment={:p}",
                    v_fn,
                    f_fn
                );
                return Err(Error::RuntimeError("Metal: Shader function lookup failed".into()));
            }

            let desc: *mut AnyObject = msg_send![objc2::class!(MTLRenderPipelineDescriptor), new];
            let _: () = msg_send![desc, setVertexFunction: v_fn];
            let _: () = msg_send![desc, setFragmentFunction: f_fn];

            let v_desc: *mut AnyObject = msg_send![objc2::class!(MTLVertexDescriptor), new];
            let attributes: *mut AnyObject = msg_send![v_desc, attributes];

            let a0: *mut AnyObject = msg_send![attributes, objectAtIndexedSubscript: 0_usize];
            let _: () = msg_send![a0, setFormat: 29_usize];
            let _: () = msg_send![a0, setOffset: 0_usize];
            let _: () = msg_send![a0, setBufferIndex: 0_usize];

            let a1: *mut AnyObject = msg_send![attributes, objectAtIndexedSubscript: 1_usize];
            let _: () = msg_send![a1, setFormat: 29_usize];
            let _: () = msg_send![a1, setOffset: 8_usize];
            let _: () = msg_send![a1, setBufferIndex: 0_usize];

            let a2: *mut AnyObject = msg_send![attributes, objectAtIndexedSubscript: 2_usize];
            let _: () = msg_send![a2, setFormat: 3_usize];
            let _: () = msg_send![a2, setOffset: 16_usize];
            let _: () = msg_send![a2, setBufferIndex: 0_usize];

            let layouts: *mut AnyObject = msg_send![v_desc, layouts];
            let l0: *mut AnyObject = msg_send![layouts, objectAtIndexedSubscript: 0_usize];
            let _: () = msg_send![l0, setStride: 20_usize];

            let _: () = msg_send![desc, setVertexDescriptor: v_desc];

            let color_attachments: *mut AnyObject = msg_send![desc, colorAttachments];
            let attach: *mut AnyObject = msg_send![color_attachments, objectAtIndexedSubscript: 0_usize];
            let _: () = msg_send![attach, setPixelFormat: 80_usize];
            let _: () = msg_send![attach, setBlendingEnabled: true];
            let _: () = msg_send![attach, setSourceRGBBlendFactor: 1_usize];
            let _: () = msg_send![attach, setDestinationRGBBlendFactor: 5_usize];
            let _: () = msg_send![attach, setSourceAlphaBlendFactor: 1_usize];
            let _: () = msg_send![attach, setDestinationAlphaBlendFactor: 5_usize];

            let pipeline: *mut AnyObject = msg_send![device, newRenderPipelineStateWithDescriptor: desc, error: std::ptr::null_mut::<*mut AnyObject>()];
            if pipeline.is_null() {
                error!("iOS GUI Metal: newRenderPipelineStateWithDescriptor returned null");
                return Err(Error::RuntimeError("Metal: Pipeline creation failed".into()));
            }

            let s_desc: *mut AnyObject = msg_send![objc2::class!(MTLSamplerDescriptor), new];
            let _: () = msg_send![s_desc, setMinFilter: 1_usize];
            let _: () = msg_send![s_desc, setMagFilter: 1_usize];
            let sampler: *mut AnyObject = msg_send![device, newSamplerStateWithDescriptor: s_desc];
            if sampler.is_null() {
                error!("iOS GUI Metal: newSamplerStateWithDescriptor returned null");
                return Err(Error::RuntimeError("Metal: Sampler creation failed".into()));
            }

            info!(
                "iOS GUI Metal: painter initialized pipeline={:p} sampler={:p}",
                pipeline,
                sampler
            );

            Ok(Self {
                pipeline_state: MetalObject(pipeline),
                sampler: MetalObject(sampler),
                textures: HashMap::new(),
            })
        }
    }

    fn update_textures(&mut self, device: *mut AnyObject, delta: egui::TexturesDelta) {
        unsafe {
            for (id, image_delta) in delta.set {
                let (patch_width, patch_height, pixels): (usize, usize, Vec<u8>) = match &image_delta.image {
                    egui::ImageData::Color(image) => {
                        let p = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                        (image.width(), image.height(), p)
                    }
                    #[allow(unreachable_patterns)]
                    _ => continue,
                };

                if let Some(pos) = image_delta.pos {
                    if let Some(texture) = self.textures.get(&id) {
                        let region = MTLRegion {
                            origin: MTLOrigin { x: pos[0], y: pos[1], z: 0 },
                            size: MTLSize { width: patch_width, height: patch_height, depth: 1 },
                        };

                        let _: () = msg_send![texture.0,
                            replaceRegion: region
                            mipmapLevel: 0_usize
                            withBytes: pixels.as_ptr() as *const c_void
                            bytesPerRow: patch_width * 4
                        ];
                    }
                } else {
                    let tex_desc: *mut AnyObject = msg_send![objc2::class!(MTLTextureDescriptor),
                        texture2DDescriptorWithPixelFormat: 70_usize,
                        width: patch_width,
                        height: patch_height,
                        mipmapped: false
                    ];

                    let texture: *mut AnyObject = msg_send![device, newTextureWithDescriptor: tex_desc];
                    if texture.is_null() {
                        error!(
                            "iOS GUI Metal: newTextureWithDescriptor returned null id={:?} size={}x{}",
                            id,
                            patch_width,
                            patch_height
                        );
                        continue;
                    }
                    let region = MTLRegion {
                        origin: MTLOrigin { x: 0, y: 0, z: 0 },
                        size: MTLSize { width: patch_width, height: patch_height, depth: 1 },
                    };

                    let _: () = msg_send![texture,
                        replaceRegion: region
                        mipmapLevel: 0_usize
                        withBytes: pixels.as_ptr() as *const c_void
                        bytesPerRow: patch_width * 4
                    ];

                    self.textures.insert(id, MetalObject(texture));
                }
            }

            for id in delta.free {
                self.textures.remove(&id);
            }
        }
    }

    pub fn paint(
        &mut self,
        device: *mut AnyObject,
        encoder: *mut AnyObject,
        screen_size: egui::Vec2,
        pixels_per_point: f32,
        textures_delta: egui::TexturesDelta,
        primitives: Vec<egui::ClippedPrimitive>,
    ) {
        self.update_textures(device, textures_delta);

        unsafe {
            let _: () = msg_send![encoder, setRenderPipelineState: self.pipeline_state.0];
            let _: () = msg_send![encoder, setFragmentSamplerState: self.sampler.0, atIndex: 0_usize];

            let uniforms = [screen_size.x, screen_size.y];
            let _: () = msg_send![encoder, setVertexBytes: uniforms.as_ptr() as *const c_void, length: 8_usize, atIndex: 1_usize];

            for egui::ClippedPrimitive { clip_rect, primitive } in primitives {
                if let egui::epaint::Primitive::Mesh(mesh) = primitive {
                    if mesh.vertices.is_empty() { continue; }

                    let clip_min = clip_rect.min;
                    let clip_max = clip_rect.max;
                    let scissor = MTLScissorRect {
                        x: (clip_min.x * pixels_per_point) as usize,
                        y: (clip_min.y * pixels_per_point) as usize,
                        width: ((clip_max.x - clip_min.x) * pixels_per_point).max(1.0) as usize,
                        height: ((clip_max.y - clip_min.y) * pixels_per_point).max(1.0) as usize,
                    };
                    let _: () = msg_send![encoder, setScissorRect: scissor];

                    if let Some(tex) = self.textures.get(&mesh.texture_id) {
                        let _: () = msg_send![encoder, setFragmentTexture: tex.0, atIndex: 0_usize];
                    }

                    let v_len = mesh.vertices.len() * std::mem::size_of::<egui::epaint::Vertex>();
                    let i_len = mesh.indices.len() * 4;

                    let vertex_buffer: *mut AnyObject = msg_send![
                        device,
                        newBufferWithBytes: mesh.vertices.as_ptr() as *const c_void,
                        length: v_len,
                        options: 0_usize
                    ];

                    let index_buffer: *mut AnyObject = msg_send![
                        device,
                        newBufferWithBytes: mesh.indices.as_ptr() as *const c_void,
                        length: i_len,
                        options: 0_usize
                    ];

                    let _: () = msg_send![
                        encoder,
                        setVertexBuffer: vertex_buffer,
                        offset: 0_usize,
                        atIndex: 0_usize
                    ];

                    let _: () = msg_send![encoder, drawIndexedPrimitives: 3_usize,
                        indexCount: mesh.indices.len(),
                        indexType: 1_usize,
                        indexBuffer: index_buffer,
                        indexBufferOffset: 0_usize,
                    ];

                    let _: () = msg_send![vertex_buffer, release];
                    let _: () = msg_send![index_buffer, release];
                }
            }
        }
    }
}
