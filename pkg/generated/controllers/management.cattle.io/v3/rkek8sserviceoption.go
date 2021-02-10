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
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
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

type RkeK8sServiceOptionHandler func(string, *v3.RkeK8sServiceOption) (*v3.RkeK8sServiceOption, error)

type RkeK8sServiceOptionController interface {
	generic.ControllerMeta
	RkeK8sServiceOptionClient

	OnChange(ctx context.Context, name string, sync RkeK8sServiceOptionHandler)
	OnRemove(ctx context.Context, name string, sync RkeK8sServiceOptionHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() RkeK8sServiceOptionCache
}

type RkeK8sServiceOptionClient interface {
	Create(*v3.RkeK8sServiceOption) (*v3.RkeK8sServiceOption, error)
	Update(*v3.RkeK8sServiceOption) (*v3.RkeK8sServiceOption, error)

	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v3.RkeK8sServiceOption, error)
	List(namespace string, opts metav1.ListOptions) (*v3.RkeK8sServiceOptionList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.RkeK8sServiceOption, err error)
}

type RkeK8sServiceOptionCache interface {
	Get(namespace, name string) (*v3.RkeK8sServiceOption, error)
	List(namespace string, selector labels.Selector) ([]*v3.RkeK8sServiceOption, error)

	AddIndexer(indexName string, indexer RkeK8sServiceOptionIndexer)
	GetByIndex(indexName, key string) ([]*v3.RkeK8sServiceOption, error)
}

type RkeK8sServiceOptionIndexer func(obj *v3.RkeK8sServiceOption) ([]string, error)

type rkeK8sServiceOptionController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewRkeK8sServiceOptionController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) RkeK8sServiceOptionController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &rkeK8sServiceOptionController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromRkeK8sServiceOptionHandlerToHandler(sync RkeK8sServiceOptionHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.RkeK8sServiceOption
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.RkeK8sServiceOption))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *rkeK8sServiceOptionController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.RkeK8sServiceOption))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateRkeK8sServiceOptionDeepCopyOnChange(client RkeK8sServiceOptionClient, obj *v3.RkeK8sServiceOption, handler func(obj *v3.RkeK8sServiceOption) (*v3.RkeK8sServiceOption, error)) (*v3.RkeK8sServiceOption, error) {
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

func (c *rkeK8sServiceOptionController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *rkeK8sServiceOptionController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *rkeK8sServiceOptionController) OnChange(ctx context.Context, name string, sync RkeK8sServiceOptionHandler) {
	c.AddGenericHandler(ctx, name, FromRkeK8sServiceOptionHandlerToHandler(sync))
}

func (c *rkeK8sServiceOptionController) OnRemove(ctx context.Context, name string, sync RkeK8sServiceOptionHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromRkeK8sServiceOptionHandlerToHandler(sync)))
}

func (c *rkeK8sServiceOptionController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *rkeK8sServiceOptionController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *rkeK8sServiceOptionController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *rkeK8sServiceOptionController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *rkeK8sServiceOptionController) Cache() RkeK8sServiceOptionCache {
	return &rkeK8sServiceOptionCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *rkeK8sServiceOptionController) Create(obj *v3.RkeK8sServiceOption) (*v3.RkeK8sServiceOption, error) {
	result := &v3.RkeK8sServiceOption{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *rkeK8sServiceOptionController) Update(obj *v3.RkeK8sServiceOption) (*v3.RkeK8sServiceOption, error) {
	result := &v3.RkeK8sServiceOption{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *rkeK8sServiceOptionController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *rkeK8sServiceOptionController) Get(namespace, name string, options metav1.GetOptions) (*v3.RkeK8sServiceOption, error) {
	result := &v3.RkeK8sServiceOption{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *rkeK8sServiceOptionController) List(namespace string, opts metav1.ListOptions) (*v3.RkeK8sServiceOptionList, error) {
	result := &v3.RkeK8sServiceOptionList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *rkeK8sServiceOptionController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *rkeK8sServiceOptionController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v3.RkeK8sServiceOption, error) {
	result := &v3.RkeK8sServiceOption{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type rkeK8sServiceOptionCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *rkeK8sServiceOptionCache) Get(namespace, name string) (*v3.RkeK8sServiceOption, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.RkeK8sServiceOption), nil
}

func (c *rkeK8sServiceOptionCache) List(namespace string, selector labels.Selector) (ret []*v3.RkeK8sServiceOption, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.RkeK8sServiceOption))
	})

	return ret, err
}

func (c *rkeK8sServiceOptionCache) AddIndexer(indexName string, indexer RkeK8sServiceOptionIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.RkeK8sServiceOption))
		},
	}))
}

func (c *rkeK8sServiceOptionCache) GetByIndex(indexName, key string) (result []*v3.RkeK8sServiceOption, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.RkeK8sServiceOption, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.RkeK8sServiceOption))
	}
	return result, nil
}
