/*
Copyright 2021 Rancher Labs, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by codegen. DO NOT EDIT.

package v3

import (
	"context"
	"time"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	v3 "github.com/rancher/rancher/pkg/apis/project.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/generic"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

type NamespacedDockerCredentialHandler func(string, *v3.NamespacedDockerCredential) (*v3.NamespacedDockerCredential, error)

type NamespacedDockerCredentialController interface {
	generic.ControllerMeta
	NamespacedDockerCredentialClient

	OnChange(ctx context.Context, name string, sync NamespacedDockerCredentialHandler)
	OnRemove(ctx context.Context, name string, sync NamespacedDockerCredentialHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() NamespacedDockerCredentialCache
}

type NamespacedDockerCredentialClient interface {
	Create(*v3.NamespacedDockerCredential) (*v3.NamespacedDockerCredential, error)
	Update(*v3.NamespacedDockerCredential) (*v3.NamespacedDockerCredential, error)

	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v3.NamespacedDockerCredential, error)
	List(namespace string, opts metav1.ListOptions) (*v3.NamespacedDockerCredentialList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.NamespacedDockerCredential, err error)
}

type NamespacedDockerCredentialCache interface {
	Get(namespace, name string) (*v3.NamespacedDockerCredential, error)
	List(namespace string, selector labels.Selector) ([]*v3.NamespacedDockerCredential, error)

	AddIndexer(indexName string, indexer NamespacedDockerCredentialIndexer)
	GetByIndex(indexName, key string) ([]*v3.NamespacedDockerCredential, error)
}

type NamespacedDockerCredentialIndexer func(obj *v3.NamespacedDockerCredential) ([]string, error)

type namespacedDockerCredentialController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewNamespacedDockerCredentialController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) NamespacedDockerCredentialController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &namespacedDockerCredentialController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromNamespacedDockerCredentialHandlerToHandler(sync NamespacedDockerCredentialHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.NamespacedDockerCredential
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.NamespacedDockerCredential))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *namespacedDockerCredentialController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.NamespacedDockerCredential))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateNamespacedDockerCredentialDeepCopyOnChange(client NamespacedDockerCredentialClient, obj *v3.NamespacedDockerCredential, handler func(obj *v3.NamespacedDockerCredential) (*v3.NamespacedDockerCredential, error)) (*v3.NamespacedDockerCredential, error) {
	if obj == nil {
		return obj, nil
	}

	copyObj := obj.DeepCopy()
	newObj, err := handler(copyObj)
	if newObj != nil {
		copyObj = newObj
	}
	if obj.ResourceVersion == copyObj.ResourceVersion && !equality.Semantic.DeepEqual(obj, copyObj) {
		return client.Update(copyObj)
	}

	return copyObj, err
}

func (c *namespacedDockerCredentialController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *namespacedDockerCredentialController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *namespacedDockerCredentialController) OnChange(ctx context.Context, name string, sync NamespacedDockerCredentialHandler) {
	c.AddGenericHandler(ctx, name, FromNamespacedDockerCredentialHandlerToHandler(sync))
}

func (c *namespacedDockerCredentialController) OnRemove(ctx context.Context, name string, sync NamespacedDockerCredentialHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromNamespacedDockerCredentialHandlerToHandler(sync)))
}

func (c *namespacedDockerCredentialController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *namespacedDockerCredentialController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *namespacedDockerCredentialController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *namespacedDockerCredentialController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *namespacedDockerCredentialController) Cache() NamespacedDockerCredentialCache {
	return &namespacedDockerCredentialCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *namespacedDockerCredentialController) Create(obj *v3.NamespacedDockerCredential) (*v3.NamespacedDockerCredential, error) {
	result := &v3.NamespacedDockerCredential{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *namespacedDockerCredentialController) Update(obj *v3.NamespacedDockerCredential) (*v3.NamespacedDockerCredential, error) {
	result := &v3.NamespacedDockerCredential{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *namespacedDockerCredentialController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *namespacedDockerCredentialController) Get(namespace, name string, options metav1.GetOptions) (*v3.NamespacedDockerCredential, error) {
	result := &v3.NamespacedDockerCredential{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *namespacedDockerCredentialController) List(namespace string, opts metav1.ListOptions) (*v3.NamespacedDockerCredentialList, error) {
	result := &v3.NamespacedDockerCredentialList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *namespacedDockerCredentialController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *namespacedDockerCredentialController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v3.NamespacedDockerCredential, error) {
	result := &v3.NamespacedDockerCredential{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type namespacedDockerCredentialCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *namespacedDockerCredentialCache) Get(namespace, name string) (*v3.NamespacedDockerCredential, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.NamespacedDockerCredential), nil
}

func (c *namespacedDockerCredentialCache) List(namespace string, selector labels.Selector) (ret []*v3.NamespacedDockerCredential, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.NamespacedDockerCredential))
	})

	return ret, err
}

func (c *namespacedDockerCredentialCache) AddIndexer(indexName string, indexer NamespacedDockerCredentialIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.NamespacedDockerCredential))
		},
	}))
}

func (c *namespacedDockerCredentialCache) GetByIndex(indexName, key string) (result []*v3.NamespacedDockerCredential, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.NamespacedDockerCredential, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.NamespacedDockerCredential))
	}
	return result, nil
}
